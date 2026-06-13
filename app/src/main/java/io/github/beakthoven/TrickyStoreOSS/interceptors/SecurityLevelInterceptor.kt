/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.interceptors

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Authorization
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import androidx.annotation.Keep
import io.github.beakthoven.TrickyStoreOSS.CertificateGen
import io.github.beakthoven.TrickyStoreOSS.CertificateHack
import io.github.beakthoven.TrickyStoreOSS.CertificateUtils
import io.github.beakthoven.TrickyStoreOSS.config.PkgConfig
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.getTransactCode
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import io.github.beakthoven.TrickyStoreOSS.putCertificateChain
import java.security.KeyPair
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap

class SecurityLevelInterceptor(
    private val original: IKeystoreSecurityLevel,
    private val level: Int
) : BinderInterceptor() {
    companion object {
        private val generateKeyTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")
        private val importKeyTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "importKey")
        private val deleteKeyTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "deleteKey")
        private val createOperationTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "createOperation")

        @Keep
        val keys = ConcurrentHashMap<Key, Info>()

        @Keep
        val keyPairs = ConcurrentHashMap<Key, Pair<KeyPair, List<Certificate>>>()

        @Keep
        val skipLeafHacks = ConcurrentHashMap<Key, Boolean>()

        /**
         * Cert cache populated by [onPostTransact] when generateKey is hacked.
         * Stores (leafCertDer, chainBlobBytes) keyed by uid+alias so that the
         * corresponding getKeyEntry call in Keystore2Interceptor returns the
         * IDENTICAL cert bytes.  hackCertificateChain is non-deterministic —
         * it produces a fresh signature on every call — so calling it from
         * generateKey and then again from getKeyEntry yields two certs with the
         * same serial but different DER bytes, which is exactly what Duck
         * Detector's Patch-mode / Binder-chain probes detect as a mismatch.
         */
        @Keep
        val hackedCertCache = ConcurrentHashMap<Key, Pair<ByteArray, ByteArray?>>()

        /**
         * Set of all aliases for which a needHack app called generateKey (regardless of
         * whether attestation was involved or the cert cache was populated).
         *
         * Used by Keystore2Interceptor.onPostTransact to decide the getKeyEntry policy:
         *  - If alias is in hackedCertCache → return the EXACT same cert that generateKey returned.
         *  - If alias is in generatedAliases but NOT in hackedCertCache → return Skip so the
         *    caller gets the REAL cert from keystore2, which is byte-for-byte identical to what
         *    generateKey returned (both paths hit the real TEE → same cert → Patch mode passes).
         *  - If alias is in neither set → fresh hackCertificateChain (isolated GMS path, etc.).
         *
         * Also used for grant tracking: any alias in this set that is subsequently granted
         * gets its nspace added to Keystore2Interceptor.blockedGrantIds to prevent the
         * grant-based getKeyEntry from calling hackCertificateChain with a different timestamp.
         */
        @Keep
        val generatedAliases = ConcurrentHashMap.newKeySet<Key>()

        @Keep
        fun getKeyResponse(uid: Int, alias: String): KeyEntryResponse? =
            keys[Key(uid, alias)]?.response

        @Keep
        fun getKeyPairs(uid: Int, alias: String): Pair<KeyPair, List<Certificate>>? =
            keyPairs[Key(uid, alias)]

        @Keep
        fun shouldSkipLeafHack(uid: Int, alias: String): Boolean =
            skipLeafHacks[Key(uid, alias)] ?: false
    }

    data class Key(val uid: Int, val alias: String)
    data class Info(val keyPair: KeyPair, val response: KeyEntryResponse)

    override fun onPreTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel
    ): Result {
        // Invalidate cached attestation state when a key is imported over an existing alias.
        // Without this, the old keybox cert would be served for a re-imported key (marker-replace detection).
        if (code == importKeyTransaction) {
            kotlin.runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
                val k = Key(callingUid, keyDescriptor.alias)
                keys.remove(k)
                keyPairs.remove(k)
                skipLeafHacks.remove(k)
                hackedCertCache.remove(k)
                generatedAliases.remove(k)
                Logger.i("importKey: cleared attestation cache uid=$callingUid alias=${keyDescriptor.alias}")
            }.onFailure { Logger.e("importKey cache clear failed", it) }
            return Skip
        }

        if (code == generateKeyTransaction) {
            Logger.i("intercept key gen uid=$callingUid pid=$callingPid")
            kotlin.runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor =
                    data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
                val attestationKeyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                val params = data.createTypedArray(KeyParameter.CREATOR)!!
                val aFlags = data.readInt()
                val entropy = data.createByteArray()
                val kgp = CertificateGen.KeyGenParameters(params)
                if (PkgConfig.needGenerate(callingUid)) {
                    val pair = CertificateGen.generateKeyPair(callingUid, keyDescriptor, attestationKeyDescriptor, kgp, level)
                        ?: return@runCatching
                    keyPairs[Key(callingUid, keyDescriptor.alias)] = Pair(pair.first, pair.second)
                    val response = buildResponse(pair.second, kgp, attestationKeyDescriptor ?: keyDescriptor)
                    keys[Key(callingUid, keyDescriptor.alias)] = Info(pair.first, response)
                    val p = Parcel.obtain()
                    p.writeNoException()
                    p.writeTypedObject(response.metadata, 0)
                    return OverrideReply(0, p)
                } else if (PkgConfig.needHack(callingUid)) {
                    // Track ALL generateKey calls for this needHack UID regardless of type.
                    // Keystore2Interceptor uses this to decide the getKeyEntry cert policy:
                    // if the alias is known but NOT in hackedCertCache, return the real TEE cert
                    // unchanged (same cert that generateKey returned) instead of calling
                    // hackCertificateChain again with a different timestamp → Patch mode passes.
                    generatedAliases.add(Key(callingUid, keyDescriptor.alias))

                    // Intercept keys that need a keybox attestation certificate.
                    //
                    // PURPOSE_ATTEST_KEY (7) and explicit attestationKeyDescriptor use OverrideReply:
                    // the real key is never stored in keystore2, so getKeyEntry returns the identical
                    // fake cert → Patch-mode / Binder-chain probes see no leaf mismatch.
                    //
                    // SIGN+challenge keys (attestationChallenge != null, purpose != 7) go through Skip
                    // so the real TEE key is created and signing operations (createOperation) succeed.
                    // Their cert chain is hacked and cached in onPostTransact; grant() is intercepted
                    // in Keystore2Interceptor to block grant-based access and prevent SELF_CHAIN_SPLIT.
                    val isAttestationKey = kgp.purpose.contains(7)
                            || attestationKeyDescriptor != null
                    if (isAttestationKey) {
                        Logger.i("Attestation key intercept (OverrideReply): uid=$callingUid alias=${keyDescriptor.alias}")
                        val pair = CertificateGen.generateKeyPair(callingUid, keyDescriptor, attestationKeyDescriptor, kgp, level)
                            ?: return@runCatching
                        keyPairs[Key(callingUid, keyDescriptor.alias)] = Pair(pair.first, pair.second)
                        val response = buildResponse(pair.second, kgp, attestationKeyDescriptor ?: keyDescriptor)
                        keys[Key(callingUid, keyDescriptor.alias)] = Info(pair.first, response)
                        SecurityLevelInterceptor.skipLeafHacks[Key(callingUid, keyDescriptor.alias)] = true
                        val p = Parcel.obtain()
                        p.writeNoException()
                        p.writeTypedObject(response.metadata, 0)
                        return OverrideReply(0, p)
                    } else {
                        // Non-attestation key (pure SIGN/ENCRYPT): let real hardware generate it.
                        // Cert hacking for these keys happens in onPostTransact if the TEE also
                        // provided an attestation cert (attestationChallenge != null path).
                        // Alias is already in generatedAliases above so getKeyEntry will not call
                        // hackCertificateChain fresh (which would produce a mismatching cert).
                        skipLeafHacks.remove(Key(callingUid, keyDescriptor.alias))
                        Logger.i("Non-attestation key, skipping intercept: uid=$callingUid alias=${keyDescriptor.alias}")
                        return Skip
                    }
                }
            }.onFailure {
                Logger.e("parse key gen request", it)
            }
        }
        return Skip
    }

    /**
     * Post-transact hook for generateKey.
     *
     * After the onPreTransact change (v2.1.12-shield1), ALL attestation generateKey calls for
     * target apps (needHack/needGenerate) return OverrideReply, so this hook is no longer
     * reachable for any target-app attestation path.  It is kept as a safety net for edge
     * cases (e.g., a target app that somehow bypasses onPreTransact) and for non-target apps
     * where it correctly returns Skip.
     *
     * The cert cache (hackedCertCache) is populated here if somehow reached so that any
     * subsequent Keystore2Interceptor.onPostTransact getKeyEntry call can return the same
     * cert bytes rather than calling hackCertificateChain again.
     */
    override fun onPostTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int
    ): Result {
        if (code != generateKeyTransaction || reply == null) return Skip
        // Non-target apps: skip so generateKey returns the real TEE cert, consistent with
        // getKeyEntry (also skipped in Keystore2Interceptor.onPostTransact for non-target).
        if (!PkgConfig.needHack(callingUid) && !PkgConfig.needGenerate(callingUid)) return Skip

        return kotlin.runCatching {
            // onPreTransact already consumed data; reset before re-reading the request.
            data.setDataPosition(0)
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                ?: return@runCatching Skip
            val attestationKeyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
            val params = data.createTypedArray(KeyParameter.CREATOR) ?: return@runCatching Skip
            val kgp = CertificateGen.KeyGenParameters(params)

            // Only handle plain signing keys with attestation challenge; all other cases
            // are already intercepted in onPreTransact and never reach onPostTransact.
            if (kgp.purpose.contains(7) || attestationKeyDescriptor != null) return@runCatching Skip
            if (kgp.attestationChallenge == null) return@runCatching Skip

            // Parse the real TEE reply.
            reply.setDataPosition(0)
            if (kotlin.runCatching { reply.readException() }.isFailure) return@runCatching Skip
            val realMetadata = reply.readTypedObject(KeyMetadata.CREATOR)
                ?: return@runCatching Skip

            // Build cert chain from TEE metadata fields.
            val leafCert = CertificateUtils.run { realMetadata.certificate?.toCertificate() }
                ?: return@runCatching Skip
            val additionalCerts = CertificateUtils.run { realMetadata.certificateChain.toCertificates() }
            val chain = (listOf(leafCert) + additionalCerts).toTypedArray<Certificate>()

            // Replace with keybox cert chain.
            val hackedChain = CertificateHack.hackCertificateChain(chain)
            realMetadata.putCertificateChain(hackedChain).getOrThrow()

            // Cache the resulting cert bytes keyed by uid+alias.  Keystore2Interceptor
            // will look this up for getKeyEntry and return the SAME bytes, making
            // generateKey and getKeyEntry byte-for-byte identical so Duck Detector's
            // Patch-mode and Binder-chain probes no longer detect a leaf mismatch.
            hackedCertCache[Key(callingUid, keyDescriptor.alias)] = Pair(
                realMetadata.certificate ?: ByteArray(0),
                realMetadata.certificateChain
            )

            Logger.i("onPostTransact: hacked+cached generateKey cert for uid=$callingUid alias=${keyDescriptor.alias}")

            // Return modified metadata — real key stays in TEE for all further operations.
            val p = Parcel.obtain()
            p.writeNoException()
            p.writeTypedObject(realMetadata, 0)
            OverrideReply(0, p)
        }.getOrElse { t ->
            Logger.e("onPostTransact generateKey hack failed uid=$callingUid", t)
            Skip
        }
    }

    private fun buildResponse(
        chain: List<Certificate>,
        params: CertificateGen.KeyGenParameters,
        descriptor: KeyDescriptor
    ): KeyEntryResponse {
        val response = KeyEntryResponse()
        val metadata = KeyMetadata()
        metadata.keySecurityLevel = level
        metadata.putCertificateChain(chain.toTypedArray()).getOrThrow()
        val d = KeyDescriptor()
        d.domain = descriptor.domain
        d.nspace = descriptor.nspace
        metadata.key = d
        val authorizations = ArrayList<Authorization>()
        var a: Authorization
        for (i in params.purpose.toList()) {
            a = Authorization()
            a.keyParameter = KeyParameter()
            a.keyParameter.tag = Tag.PURPOSE
            a.keyParameter.value = KeyParameterValue.keyPurpose(i)
            a.securityLevel = level
            authorizations.add(a)
        }
        for (i in params.digest.toList()) {
            a = Authorization()
            a.keyParameter = KeyParameter()
            a.keyParameter.tag = Tag.DIGEST
            a.keyParameter.value = KeyParameterValue.digest(i)
            a.securityLevel = level
            authorizations.add(a)
        }
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.ALGORITHM
        a.keyParameter.value = KeyParameterValue.algorithm(params.algorithm)
        a.securityLevel = level
        authorizations.add(a)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.KEY_SIZE
        a.keyParameter.value = KeyParameterValue.integer(params.keySize)
        a.securityLevel = level
        authorizations.add(a)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.EC_CURVE
        a.keyParameter.value = KeyParameterValue.ecCurve(params.ecCurve)
        a.securityLevel = level
        authorizations.add(a)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.NO_AUTH_REQUIRED
        a.keyParameter.value = KeyParameterValue.boolValue(true)
        a.securityLevel = level
        authorizations.add(a)
        metadata.authorizations = authorizations.toTypedArray<Authorization>()
        response.metadata = metadata
        response.iSecurityLevel = original
        return response
    }
}
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
import java.security.MessageDigest
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
         * Full hacked [KeyEntryResponse] keyed by the OWNER's uid+alias.
         *
         * Used to mirror grant reads: when a hacked key is granted to another UID,
         * getKeyEntry(GRANT) returns this exact response so the grantee (even an
         * isolated process that cannot talk to keystore2) gets a byte-for-byte
         * identical chain. This is how official TrickyStore keeps Grant self-domain
         * and Grant isolated-domain probes aligned (no CHAIN_SPLIT) without throwing
         * an exception that would otherwise trip the timing side-channel probe.
         */
        @Keep
        val hackedResponseCache = ConcurrentHashMap<Key, KeyEntryResponse>()

        /**
         * Maps a keystore2 KEY_ID (the numeric id keystore2 assigns to a loaded key and
         * returns in metadata.key.nspace) back to the OWNER's (uid, alias).
         *
         * Duck Detector switches every follow-up read/grant to a KEY_ID-domain descriptor
         * (domain=4) which carries NO alias, so an alias-keyed cache would miss and trigger
         * a fresh non-deterministic hack → chain split. This map lets KEY_ID reads and
         * KEY_ID-based grants resolve to the same cached cert as the original alias.
         */
        @Keep
        val keyIdToOwner = ConcurrentHashMap<Long, Key>()

        /**
         * Deterministic cert cache keyed by the SHA-256 of the REAL TEE leaf certificate.
         *
         * This is the backbone of cross-path consistency. A key's real hardware certificate
         * is byte-for-byte identical no matter HOW it is read (APP alias, KEY_ID, GRANT, the
         * public/hidden Java KeyStore, or a raw private binder), because the certificate is a
         * property of the key, not of the descriptor used to fetch it. By caching the hacked
         * output under the hash of the real input leaf, every read of the same underlying key
         * returns the IDENTICAL hacked bytes — even Duck Detector's Grant self-domain "Hidden"
         * stage that bypasses KeyStoreManager and reads the GRANT namespace through a separate
         * binder surface. No grant-id / key-id tracking is required for consistency; the real
         * cert is the natural identity. hackCertificateChain is non-deterministic, so without
         * this the same key hacked twice produces two different DER leaves → CHAIN_SPLIT.
         */
        @Keep
        val hackedByRealLeaf = ConcurrentHashMap<String, Pair<ByteArray, ByteArray?>>()

        /** SHA-256 hex of a DER blob, used as the [hackedByRealLeaf] key. */
        @Keep
        fun leafHashKey(der: ByteArray?): String? {
            if (der == null || der.isEmpty()) return null
            return runCatching {
                MessageDigest.getInstance("SHA-256").digest(der)
                    .joinToString(separator = "") { b -> "%02x".format(b) }
            }.getOrNull()
        }

        /**
         * True if the key's metadata reports an IMPORTED / SECURELY_IMPORTED origin.
         *
         * Imported keys carry a marker leaf the caller set explicitly (e.g. Duck Detector's
         * ImportKey-retained-narrative probe imports the keybox fixture cert). They are never
         * hardware-attested and Play Integrity only uses GENERATED keys, so we MUST return the
         * real imported cert untouched — neither hacking it (which would change the marker) nor
         * serving a stale hacked chain cached under the same alias from a prior generateKey.
         */
        @Keep
        fun isImportedOrigin(metadata: KeyMetadata?): Boolean {
            val auths = metadata?.authorizations ?: return false
            for (a in auths) {
                val kp = a?.keyParameter ?: continue
                if (kp.tag == Tag.ORIGIN) {
                    val v = kp.value ?: return false
                    val origin = runCatching { v.origin }.getOrNull()
                        ?: runCatching { v.integer }.getOrNull()
                        ?: return false
                    // android.hardware.security.keymint.KeyOrigin: IMPORTED=2, SECURELY_IMPORTED=4
                    return origin == ORIGIN_IMPORTED || origin == ORIGIN_SECURELY_IMPORTED
                }
            }
            return false
        }

        // android.hardware.security.keymint.KeyOrigin values.
        private const val ORIGIN_IMPORTED = 2
        private const val ORIGIN_SECURELY_IMPORTED = 4

        // android.system.keystore2.Domain values.
        const val DOMAIN_APP = 0
        const val DOMAIN_GRANT = 1
        const val DOMAIN_SELINUX = 2
        const val DOMAIN_KEY_ID = 4

        /**
         * Legacy membership set kept only as a weak signal for diagnostics/backward
         * compatibility. It must never decide getKeyEntry passthrough by itself:
         * Play Integrity/GMS needs the keybox chain on every cache-miss path.
         */
        @Keep
        val generatedAliases = ConcurrentHashMap.newKeySet<Key>()

        enum class ChainKind {
            NONE,
            REAL_TEE,
            KEYBOX_HACKED,
            SYNTHETIC
        }

        data class AliasState(
            val uid: Int,
            val alias: String,
            val policy: PkgConfig.AttestationPolicy,
            val purposes: Set<Int>,
            val hasChallenge: Boolean,
            val usesAttestationKey: Boolean,
            @Volatile var returnedChainKind: ChainKind = ChainKind.NONE,
            @Volatile var cachedLeaf: ByteArray? = null,
            @Volatile var cachedChain: ByteArray? = null,
            @Volatile var nativeKeyExists: Boolean = false
        ) {
            val integrityCritical: Boolean
                get() = policy == PkgConfig.AttestationPolicy.INTEGRITY_CRITICAL

            val detectorLike: Boolean
                get() = policy == PkgConfig.AttestationPolicy.DETECTOR

            val ownerPathModified: Boolean
                get() = returnedChainKind == ChainKind.KEYBOX_HACKED ||
                        returnedChainKind == ChainKind.SYNTHETIC ||
                        cachedLeaf != null
        }

        @Keep
        val aliasStates = ConcurrentHashMap<Key, AliasState>()

        @Keep
        fun getKeyResponse(uid: Int, alias: String): KeyEntryResponse? =
            keys[Key(uid, alias)]?.response

        @Keep
        fun getKeyPairs(uid: Int, alias: String): Pair<KeyPair, List<Certificate>>? =
            keyPairs[Key(uid, alias)]

        @Keep
        fun shouldSkipLeafHack(uid: Int, alias: String): Boolean =
            skipLeafHacks[Key(uid, alias)] ?: false

        @Keep
        fun getAliasState(uid: Int, alias: String?): AliasState? =
            alias?.let { aliasStates[Key(uid, it)] }

        @Keep
        fun clearAliasState(uid: Int, alias: String) {
            val k = Key(uid, alias)
            keys.remove(k)
            keyPairs.remove(k)
            skipLeafHacks.remove(k)
            hackedCertCache.remove(k)
            hackedResponseCache.remove(k)
            generatedAliases.remove(k)
            aliasStates.remove(k)
            keyIdToOwner.entries.removeAll { it.value == k }
        }

        /** Record the KEY_ID -> owner mapping from a metadata.key descriptor, if present. */
        @Keep
        fun rememberKeyId(metadataKey: KeyDescriptor?, owner: Key) {
            if (metadataKey != null && metadataKey.domain == DOMAIN_KEY_ID) {
                keyIdToOwner[metadataKey.nspace] = owner
            }
        }

        @Keep
        fun cacheHackedCert(uid: Int, alias: String, leaf: ByteArray, chain: ByteArray?) {
            val k = Key(uid, alias)
            hackedCertCache[k] = Pair(leaf, chain)
            aliasStates[k]?.let { state ->
                state.cachedLeaf = leaf
                state.cachedChain = chain
                state.returnedChainKind = ChainKind.KEYBOX_HACKED
            }
        }
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
                clearAliasState(callingUid, keyDescriptor.alias)
                Logger.i("importKey: cleared attestation cache uid=$callingUid alias=${keyDescriptor.alias}")
            }.onFailure { Logger.e("importKey cache clear failed", it) }
            return Skip
        }

        if (code == deleteKeyTransaction) {
            kotlin.runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
                clearAliasState(callingUid, keyDescriptor.alias)
                Logger.i("deleteKey: cleared attestation cache uid=$callingUid alias=${keyDescriptor.alias}")
            }.onFailure { Logger.e("deleteKey cache clear failed", it) }
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
                // Regenerating over an existing alias must invalidate any stale cached cert,
                // otherwise getKeyEntry would serve the previous key's chain (Update-persistence
                // STALE_TEE_RESPONSE detection).
                clearAliasState(callingUid, keyDescriptor.alias)
                if (PkgConfig.needGenerate(callingUid)) {
                    aliasStates[Key(callingUid, keyDescriptor.alias)] = AliasState(
                        uid = callingUid,
                        alias = keyDescriptor.alias,
                        policy = PkgConfig.policyForUid(callingUid),
                        purposes = kgp.purpose.toSet(),
                        hasChallenge = kgp.attestationChallenge != null,
                        usesAttestationKey = attestationKeyDescriptor != null,
                        returnedChainKind = ChainKind.SYNTHETIC,
                        nativeKeyExists = false
                    )
                    val pair = CertificateGen.generateKeyPair(callingUid, keyDescriptor, attestationKeyDescriptor, kgp, level)
                        ?: return@runCatching
                    keyPairs[Key(callingUid, keyDescriptor.alias)] = Pair(pair.first, pair.second)
                    val response = buildResponse(pair.second, kgp, attestationKeyDescriptor ?: keyDescriptor)
                    keys[Key(callingUid, keyDescriptor.alias)] = Info(pair.first, response)
                    hackedResponseCache[Key(callingUid, keyDescriptor.alias)] = response
                    val p = Parcel.obtain()
                    p.writeNoException()
                    p.writeTypedObject(response.metadata, 0)
                    return OverrideReply(0, p)
                } else if (PkgConfig.needHack(callingUid)) {
                    generatedAliases.add(Key(callingUid, keyDescriptor.alias))
                    val policy = PkgConfig.policyForUid(callingUid)

                    // Official-TrickyStore model: NEVER synthesize a fake key. Always let the
                    // REAL key be created in keystore2 via Continue (including PURPOSE_ATTEST_KEY
                    // and keys built with an app-supplied attestation key), then leaf-hack the
                    // returned chain in onPostTransact.
                    //
                    // Why this matters: synthesizing the key with OverrideReply means the real
                    // key never lands in keystore2, so any later OPERATION on it (sign / attest
                    // another key) fails with "key not found". That is exactly what broke the
                    // timing side-channel probe (it threw during measurement → no ms shown) and,
                    // critically, what breaks apps like Revolut that generate an attestation key
                    // and then perform crypto with it. Keeping the real key makes operations run
                    // natively, just like official TrickyStore. getKeyEntry stays consistent via
                    // the leaf hash cache (generateKey == getKeyEntry == Java KeyStore).
                    val isAttestationKey = kgp.purpose.contains(7)
                            || attestationKeyDescriptor != null
                    aliasStates[Key(callingUid, keyDescriptor.alias)] = AliasState(
                        uid = callingUid,
                        alias = keyDescriptor.alias,
                        policy = policy,
                        purposes = kgp.purpose.toSet(),
                        hasChallenge = kgp.attestationChallenge != null,
                        usesAttestationKey = isAttestationKey,
                        returnedChainKind = ChainKind.REAL_TEE,
                        nativeKeyExists = true
                    )
                    // Oversized attestation challenge → let native keymint reject it
                    // (Duck Detector OversizedChallenge probe expects the rejection).
                    if (isAttestationKey && (kgp.attestationChallenge?.size ?: 0) > 128) {
                        Logger.i("Oversized attestation challenge, passthrough to native rejection: uid=$callingUid alias=${keyDescriptor.alias}")
                        return Skip
                    }
                    skipLeafHacks.remove(Key(callingUid, keyDescriptor.alias))
                    return if (kgp.attestationChallenge != null) {
                        // Real key created in TEE; post-transact leaf-hacks + caches the chain.
                        Logger.i("Attested key, Continue for post-transact hack+cache: uid=$callingUid alias=${keyDescriptor.alias} attestKey=$isAttestationKey")
                        Continue
                    } else {
                        // No attestation challenge → no attestation cert to hack; passthrough.
                        Logger.i("Non-attestation key (no challenge), passthrough: uid=$callingUid alias=${keyDescriptor.alias}")
                        Skip
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
     * Reached for SIGN+challenge keys of target apps (onPreTransact returns Continue for them).
     * This is where the real TEE key's attestation chain is leaf-hacked with the keybox cert
     * and the result is cached so getKeyEntry / Java KeyStore / grant reads all return the
     * IDENTICAL DER bytes (Duck Detector Patch-mode / Binder-chain consistency). The real key
     * stays in keystore2, so signing/operation paths behave natively.
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

            // Leaf-hack EVERY attested key — including PURPOSE_ATTEST_KEY and keys built with an
            // app-supplied attestation key. hackCertificateChain copies the real attestation
            // extension (challenge, security level, boot state) onto a keybox-signed leaf and
            // replaces the chain with the keybox CA chain, so the result is consistent regardless
            // of how the key was attested. Only keys with NO challenge have no cert to hack.
            if (kgp.attestationChallenge == null) return@runCatching Skip

            // Parse the real TEE reply.
            reply.setDataPosition(0)
            if (kotlin.runCatching { reply.readException() }.isFailure) return@runCatching Skip
            val realMetadata = reply.readTypedObject(KeyMetadata.CREATOR)
                ?: return@runCatching Skip

            // Capture the REAL leaf hash BEFORE hacking — this is the cross-path identity that
            // getKeyEntry (alias/KEY_ID/GRANT) will use to serve these exact hacked bytes.
            val realLeafHash = leafHashKey(realMetadata.certificate)

            // Build cert chain from TEE metadata fields.
            val leafCert = CertificateUtils.run { realMetadata.certificate?.toCertificate() }
                ?: return@runCatching Skip
            val additionalCerts = CertificateUtils.run { realMetadata.certificateChain.toCertificates() }
            val chain = (listOf(leafCert) + additionalCerts).toTypedArray<Certificate>()

            // Replace with keybox cert chain.
            val hackedChain = CertificateHack.hackCertificateChain(chain)
            realMetadata.putCertificateChain(hackedChain).getOrThrow()

            // Deterministic cache: any later read of this key (whatever the descriptor/path)
            // resolves the same real leaf hash and gets these identical hacked bytes.
            if (realLeafHash != null) {
                hackedByRealLeaf[realLeafHash] = Pair(
                    realMetadata.certificate ?: ByteArray(0),
                    realMetadata.certificateChain
                )
            }

            // Cache the resulting cert bytes keyed by uid+alias.  Keystore2Interceptor
            // will look this up for getKeyEntry and return the SAME bytes, making
            // generateKey and getKeyEntry byte-for-byte identical so Duck Detector's
            // Patch-mode and Binder-chain probes no longer detect a leaf mismatch.
            cacheHackedCert(
                callingUid,
                keyDescriptor.alias,
                realMetadata.certificate ?: ByteArray(0),
                realMetadata.certificateChain
            )

            // Cache a full response too so grant reads (incl. isolated grantees that cannot
            // reach keystore2) can be mirrored with these exact bytes.
            val grantResponse = KeyEntryResponse()
            grantResponse.metadata = realMetadata
            grantResponse.iSecurityLevel = original
            hackedResponseCache[Key(callingUid, keyDescriptor.alias)] = grantResponse

            // Map the KEY_ID keystore2 assigned to this key back to the owner alias so that
            // KEY_ID-domain reads/grants (which carry no alias) resolve to this same cert.
            rememberKeyId(realMetadata.key, Key(callingUid, keyDescriptor.alias))

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
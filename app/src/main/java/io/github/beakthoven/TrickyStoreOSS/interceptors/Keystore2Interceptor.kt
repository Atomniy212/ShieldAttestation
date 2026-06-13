/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.interceptors

import android.annotation.SuppressLint
import android.hardware.security.keymint.SecurityLevel
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import io.github.beakthoven.TrickyStoreOSS.CertificateHack
import io.github.beakthoven.TrickyStoreOSS.CertificateUtils
import io.github.beakthoven.TrickyStoreOSS.KeyBoxUtils
import io.github.beakthoven.TrickyStoreOSS.config.PkgConfig
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.createTypedObjectReply
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.getTransactCode
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.hasException
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import io.github.beakthoven.TrickyStoreOSS.putCertificateChain
import java.util.concurrent.ConcurrentHashMap

@SuppressLint("BlockedPrivateApi")
object Keystore2Interceptor : BaseKeystoreInterceptor() {
    private val getKeyEntryTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "getKeyEntry")
    private val deleteKeyTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "deleteKey")
    private val grantTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "grant")
    private val updateSubcomponentTransaction =
        kotlin.runCatching { getTransactCode(IKeystoreService.Stub::class.java, "updateSubcomponent") }
            .getOrDefault(-1)

    private val DOMAIN_GRANT = SecurityLevelInterceptor.DOMAIN_GRANT
    private val DOMAIN_KEY_ID = SecurityLevelInterceptor.DOMAIN_KEY_ID

    /**
     * Maps a grant id (the nspace of a GRANT-domain KeyDescriptor returned by grant())
     * back to the OWNER's (uid, alias) whose attestation chain we leaf-hacked.
     *
     * Instead of blocking grant reads (which produced a KEY_NOT_FOUND exception that
     * Duck Detector's timing side-channel probe captured, and still left a CHAIN_SPLIT),
     * we MIRROR the owner's exact cached cert/response on getKeyEntry(GRANT). The grantee
     * — including isolated processes that cannot reach keystore2 — receives byte-for-byte
     * identical bytes, so Grant self-domain / isolated-domain probes see aligned chains.
     * This matches official TrickyStore, which keeps grants consistent rather than failing.
     */
    private val grantedCertKeys = ConcurrentHashMap<Long, GrantInfo>()

    /**
     * Per-grant binding: the owner whose hacked cert we mirror, plus the grantee UID the
     * grant was issued to. Stock keystore2 binds a grant handle to its grantee — only that
     * UID may read it. We therefore mirror ONLY when callingUid == granteeUid; a non-grantee
     * read (e.g. the owner replaying an isolated grant handle) must fall through to keystore2's
     * KEY_NOT_FOUND, otherwise Duck Detector flags NON_GRANTEE_READBACK_ALLOWED (caller binding).
     */
    private data class GrantInfo(val owner: SecurityLevelInterceptor.Key, val granteeUid: Int)

    override val serviceName = "android.system.keystore2.IKeystoreService/default"
    override val processName = "keystore2"
    override val injectionCommand = "exec ./inject `pidof keystore2` libShieldAttestation.so entry"

    private var teeInterceptor: SecurityLevelInterceptor? = null
    private var strongBoxInterceptor: SecurityLevelInterceptor? = null
    
    override fun onInterceptorSetup(service: IBinder, backdoor: IBinder) {
        setupSecurityLevelInterceptors(service, backdoor)
    }
    
    private fun setupSecurityLevelInterceptors(service: IBinder, backdoor: IBinder) {
        val ks = IKeystoreService.Stub.asInterface(service)
        
        val tee = kotlin.runCatching { ks.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT) }
            .getOrNull()
        if (tee != null) {
            Logger.i("Registering for TEE SecurityLevel: $tee")
            val interceptor = SecurityLevelInterceptor(tee, SecurityLevel.TRUSTED_ENVIRONMENT)
            registerBinderInterceptor(backdoor, tee.asBinder(), interceptor)
            teeInterceptor = interceptor
        } else {
            Logger.i("No TEE SecurityLevel found")
        }
        
        val strongBox = kotlin.runCatching { ks.getSecurityLevel(SecurityLevel.STRONGBOX) }
            .getOrNull()
        if (strongBox != null) {
            Logger.i("Registering for StrongBox SecurityLevel: $strongBox")
            val interceptor = SecurityLevelInterceptor(strongBox, SecurityLevel.STRONGBOX)
            registerBinderInterceptor(backdoor, strongBox.asBinder(), interceptor)
            strongBoxInterceptor = interceptor
        } else {
            Logger.i("No StrongBox SecurityLevel found")
        }
    }

    private fun isIsolatedUid(uid: Int): Boolean = (uid % 100000) >= 90000

    override fun onPreTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel
    ): Result {
        // getKeyEntry: handle BEFORE the isIsolatedUid gate so GRANT-domain reads are mirrored
        // for BOTH non-isolated and isolated callers.
        if (code == getKeyEntryTransaction && KeyBoxUtils.hasKeyboxes()) {
            Logger.d("intercept pre  $target uid=$callingUid pid=$callingPid dataSz=${data.dataSize()}")
            try {
                data.enforceInterface(IKeystoreService.DESCRIPTOR)
                val descriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return Skip

                // GRANT-domain read: do NOT pre-mirror. Let native keystore2 enforce the grant's
                // access vector (GET_INFO, USE, etc.) and grantee binding itself, then leaf-hack
                // the returned chain in onPostTransact via the real-leaf hash cache so the grantee
                // still gets bytes identical to the owner (consistent self/isolated-domain chains).
                //
                // Pre-mirroring bypassed the GET_INFO permission check — a grantee with accessVector
                // lacking GET_INFO could still read metadata, which stock keystore2 forbids. That is
                // the GET_KEY_ENTRY_WITHOUT_GET_INFO_ALLOWED anomaly Duck Detector flags, and exactly
                // the behaviour official TrickyStore avoids by never intercepting grant reads.
                if (descriptor.domain == DOMAIN_GRANT) {
                    Logger.i("GRANT read uid=$callingUid nspace=${descriptor.nspace}; Continue (native perms + post leaf-hack)")
                    return Continue
                }

                // Standard isolated-UID gate: isolated processes must not hit the alias cache
                // (cache is keyed by uid+alias; isolated UIDs are ephemeral, so a miss would
                // return a null response and crash the caller).
                if (isIsolatedUid(callingUid)) return Skip

                // KEY_ID-domain read (Duck Detector's follow-up descriptor) carries no alias.
                // Continue so onPostTransact resolves the owner via keyIdToOwner and serves the
                // SAME cached cert as the alias/generate path (otherwise a fresh hack → split).
                if (descriptor.domain == DOMAIN_KEY_ID && PkgConfig.needLeafHack(callingUid)) {
                    Logger.i("KEY_ID read uid=$callingUid nspace=${descriptor.nspace}; Continue for post resolve")
                    return Continue
                }

                if (PkgConfig.needGenerate(callingUid)) {
                    val response = SecurityLevelInterceptor.getKeyResponse(callingUid, descriptor.alias)
                    if (response != null) {
                        Logger.i("Found generated response for uid=$callingUid alias=${descriptor.alias}")
                        return createTypedObjectReply(response)
                    } else {
                        Logger.e("No generated response found for uid=$callingUid alias=${descriptor.alias}")
                        val nullParcel = Parcel.obtain()
                        nullParcel.writeTypedObject(null as KeyEntryResponse?, 0)
                        return OverrideReply(0, nullParcel)
                    }
                } else if (PkgConfig.needLeafHack(callingUid)) {
                    if (SecurityLevelInterceptor.shouldSkipLeafHack(callingUid, descriptor.alias)) {
                        Logger.i("skip leaf hack for uid=$callingUid alias=${descriptor.alias}")
                        val response = SecurityLevelInterceptor.getKeyResponse(callingUid, descriptor.alias)
                        if (response != null) {
                            Logger.i("Found generated response for uid=$callingUid alias=${descriptor.alias}")
                            return createTypedObjectReply(response)
                        } else {
                            Logger.e("No generated response found for uid=$callingUid alias=${descriptor.alias}")
                            val nullParcel = Parcel.obtain()
                            nullParcel.writeTypedObject(null as KeyEntryResponse?, 0)
                            return OverrideReply(0, nullParcel)
                        }
                    } else {
                        Logger.i("proceeding with leaf hack for uid=$callingUid alias=${descriptor.alias}")
                        return Continue
                    }
                }
                return Skip
            } catch (e: Exception) {
                Logger.e("Exception in onPreTransact uid=$callingUid pid=$callingPid!", e)
                return Skip
            }
        }

        // grant() / updateSubcomponent(): NOT intercepted. Official TrickyStore only hooks
        // getKeyEntry; touching grant/updateSubcomponent added non-stock behaviour that real
        // anti-tamper SDKs can detect. We let both flow straight to native keystore2.

        // For all other transaction codes, skip isolated UIDs entirely.
        if (isIsolatedUid(callingUid)) return Skip

        return Skip
    }

    /**
     * Resolve the owner (uid, alias) for a key descriptor that may be APP-domain (has alias)
     * or KEY_ID-domain (no alias, resolved via keyIdToOwner).
     */
    private fun resolveOwnerKey(callingUid: Int, descriptor: KeyDescriptor?): SecurityLevelInterceptor.Key? {
        if (descriptor == null) return null
        val alias = descriptor.alias
        return when {
            descriptor.domain == DOMAIN_KEY_ID -> SecurityLevelInterceptor.keyIdToOwner[descriptor.nspace]
            alias != null -> SecurityLevelInterceptor.Key(callingUid, alias)
            else -> null
        }
    }

    private fun handleUpdateSubcomponentPre(callingUid: Int, data: Parcel) {
        try {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val descriptor = data.readTypedObject(KeyDescriptor.CREATOR)
            // The cert-update path arrives as a KEY_ID (alias=null) descriptor; resolve the
            // owner so we can drop the now-stale cached chain for that key.
            val ownerKey = resolveOwnerKey(callingUid, descriptor) ?: return
            SecurityLevelInterceptor.clearAliasState(ownerKey.uid, ownerKey.alias)
            Logger.i("updateSubcomponent: invalidated cache for owner=$ownerKey uid=$callingUid (passthrough to hardware)")
        } catch (e: Exception) {
            Logger.e("handleUpdateSubcomponentPre failed uid=$callingUid", e)
        }
    }

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
        if (target != keystore || reply == null) return Skip
        if (reply.hasException()) return Skip
        val p = Parcel.obtain()
        Logger.d("intercept post $target uid=$callingUid pid=$callingPid dataSz=${data.dataSize()} replySz=${reply.dataSize()}")

        if (code == deleteKeyTransaction && resultCode == 0) {
            data.enforceInterface("android.system.keystore2.IKeystoreService")

            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
            if (keyDescriptor == null || keyDescriptor.domain == 0) return Skip

            SecurityLevelInterceptor.clearAliasState(callingUid, keyDescriptor.alias)

            return Skip
        } else if (code == getKeyEntryTransaction) {
            // Uniform keybox substitution — NO app is on a deny list. Every app (incl. Duck
            // Detector and Revolut) must receive the keybox chain so bootloader/TEE checks pass.
            //
            // Consistency is guaranteed by the cert cache: generateKey leaf-hacked the chain in
            // SecurityLevelInterceptor.onPostTransact (it now returns Continue, so post fires),
            // and we return that SAME cached cert here → generateKey == getKeyEntry == Java
            // KeyStore. hackCertificateChain is non-deterministic, so calling it twice would
            // produce different DER; the cache is what keeps the bytes identical.
            try {
                data.enforceInterface("android.system.keystore2.IKeystoreService")
                val reqDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                val isGrant = reqDescriptor?.domain == DOMAIN_GRANT
                // Resolve the cache key: GRANT reads map via grant id, KEY_ID reads via keyId,
                // otherwise uid+alias. This keeps every descriptor form pointing at one cert.
                val cacheKey: SecurityLevelInterceptor.Key? = when {
                    isGrant -> reqDescriptor?.let { grantedCertKeys[it.nspace]?.owner }
                    reqDescriptor?.domain == DOMAIN_KEY_ID ->
                        reqDescriptor.let { SecurityLevelInterceptor.keyIdToOwner[it.nspace] }
                    reqDescriptor?.alias != null ->
                        SecurityLevelInterceptor.Key(callingUid, reqDescriptor.alias)
                    else -> null
                }
                // Act for target apps, isolated GMS workers, or tracked GRANT reads only.
                val trackedGrant = isGrant && cacheKey != null
                if (!trackedGrant && !PkgConfig.needLeafHack(callingUid) &&
                    !PkgConfig.needGenerate(callingUid) && !isIsolatedUid(callingUid)) {
                    p.recycle()
                    return Skip
                }
                val response = reply.readTypedObject(KeyEntryResponse.CREATOR)
                if (response != null) {
                    // Imported keys (e.g. the keybox-fixture marker the ImportKey-narrative probe
                    // sets) must be returned untouched: never hack the marker leaf, never serve a
                    // stale hacked chain cached under the same alias from a prior generateKey.
                    if (SecurityLevelInterceptor.isImportedOrigin(response.metadata)) {
                        Logger.i("getKeyEntry: imported-origin key, passthrough uid=$callingUid key=$cacheKey")
                        p.recycle()
                        return Skip
                    }

                    // PRIMARY consistency: resolve the hacked bytes by the REAL leaf hash. The
                    // real cert is identical across every read path, so this returns byte-for-byte
                    // identical bytes for owner/grant/KEY_ID reads alike — including the Grant
                    // self-domain "Hidden" stage that bypasses the alias/grant-id caches.
                    val realLeafHash =
                        SecurityLevelInterceptor.leafHashKey(response.metadata?.certificate)
                    val hashCached = realLeafHash?.let { SecurityLevelInterceptor.hackedByRealLeaf[it] }
                    if (hashCached != null) {
                        response.metadata?.let { meta ->
                            meta.certificate = hashCached.first
                            meta.certificateChain = hashCached.second
                        }
                        // Keep the alias/grant caches warm for the isolated-grant pre mirror.
                        if (cacheKey != null) {
                            SecurityLevelInterceptor.cacheHackedCert(
                                cacheKey.uid, cacheKey.alias, hashCached.first, hashCached.second
                            )
                            SecurityLevelInterceptor.hackedResponseCache[cacheKey] = response
                            SecurityLevelInterceptor.rememberKeyId(response.metadata?.key, cacheKey)
                        }
                        Logger.i("getKeyEntry: real-leaf cache hit uid=$callingUid key=$cacheKey grant=$isGrant")
                        return createTypedObjectReply(response)
                    }

                    // Legacy alias/grant cache-hit (synthetic/mirrored paths).
                    val cached = cacheKey?.let { SecurityLevelInterceptor.hackedCertCache[it] }
                    if (cached != null) {
                        response.metadata?.let { meta ->
                            meta.certificate = cached.first
                            meta.certificateChain = cached.second
                        }
                        Logger.i("getKeyEntry: cert cache hit uid=$callingUid key=$cacheKey grant=$isGrant")
                        return createTypedObjectReply(response)
                    }
                    val chain = CertificateUtils.run { response.getCertificateChain() }
                    if (chain != null) {
                        val newChain = CertificateHack.hackCertificateChain(chain)
                        if (newChain === chain) {
                            // No attestation extension (e.g. pure signing cert) — leave it as-is
                            // so we don't re-wrap a non-attestation entry.
                            Logger.i("getKeyEntry: no attestation extension, passthrough uid=$callingUid key=$cacheKey")
                            p.recycle()
                            return Skip
                        }
                        response.putCertificateChain(newChain).getOrThrow()
                        // Deterministic cache keyed by the real leaf hash so EVERY later read of
                        // this key (any descriptor / any binder surface) returns these bytes.
                        if (realLeafHash != null) {
                            response.metadata?.let { meta ->
                                SecurityLevelInterceptor.hackedByRealLeaf[realLeafHash] = Pair(
                                    meta.certificate ?: ByteArray(0),
                                    meta.certificateChain
                                )
                            }
                        }
                        // Cache under the resolved owner key so all later reads stay identical.
                        if (cacheKey != null) {
                            response.metadata?.let { meta ->
                                SecurityLevelInterceptor.cacheHackedCert(
                                    cacheKey.uid,
                                    cacheKey.alias,
                                    meta.certificate ?: ByteArray(0),
                                    meta.certificateChain
                                )
                                SecurityLevelInterceptor.hackedResponseCache[cacheKey] = response
                                // Map the KEY_ID to the owner so KEY_ID-domain reads stay aligned.
                                SecurityLevelInterceptor.rememberKeyId(meta.key, cacheKey)
                            }
                        }
                        Logger.i("Hacked certificate for uid=$callingUid grant=$isGrant key=$cacheKey")
                        return createTypedObjectReply(response)
                    } else {
                        p.recycle()
                    }
                } else {
                    p.recycle()
                }
            } catch (t: Throwable) {
                Logger.e("failed to hack certificate chain of uid=$callingUid pid=$callingPid!", t)
                p.recycle()
            }
        }
        return Skip
    }
}

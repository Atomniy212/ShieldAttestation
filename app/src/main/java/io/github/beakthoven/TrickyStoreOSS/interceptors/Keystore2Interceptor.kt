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
    private val grantedCertKeys = ConcurrentHashMap<Long, SecurityLevelInterceptor.Key>()

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

                // GRANT-domain read: mirror the owner's exact hacked response so the grantee
                // (even an isolated process that cannot reach keystore2) gets byte-for-byte
                // identical bytes → no CHAIN_SPLIT, no injected exception (timing probe clean).
                if (descriptor.domain == 2 /* GRANT */) {
                    val ownerKey = grantedCertKeys[descriptor.nspace]
                    if (ownerKey != null) {
                        val cachedResp = SecurityLevelInterceptor.hackedResponseCache[ownerKey]
                        if (cachedResp != null) {
                            Logger.i("Mirroring GRANT nspace=${descriptor.nspace} -> owner=$ownerKey uid=$callingUid (isolated=${isIsolatedUid(callingUid)})")
                            return createTypedObjectReply(cachedResp)
                        }
                        // No full response cached: let it through and fix the cert in post.
                        Logger.i("GRANT nspace=${descriptor.nspace} owner=$ownerKey but no cached response; Continue for post mirror")
                        return Continue
                    }
                    // Unknown grant id: not one of ours, behave normally.
                }

                // Standard isolated-UID gate: isolated processes must not hit the alias cache
                // (cache is keyed by uid+alias; isolated UIDs are ephemeral, so a miss would
                // return a null response and crash the caller).
                if (isIsolatedUid(callingUid)) return Skip

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
                } else if (PkgConfig.needHack(callingUid)) {
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

        // For all other transaction codes, skip isolated UIDs entirely.
        if (isIsolatedUid(callingUid)) return Skip

        return Skip
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
        } else if (code == grantTransaction) {
            // Record the grant id → owner mapping only for aliases we actually leaf-hacked
            // (cert/response cached). Pure native keys are not tracked, so their grants pass
            // through untouched and stay consistent by construction.
            if (PkgConfig.needHack(callingUid) || PkgConfig.needGenerate(callingUid)) {
                try {
                    data.enforceInterface("android.system.keystore2.IKeystoreService")
                    val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                    val alias = keyDescriptor?.alias
                    if (alias != null) {
                        val ownerKey = SecurityLevelInterceptor.Key(callingUid, alias)
                        val hacked = SecurityLevelInterceptor.hackedCertCache.containsKey(ownerKey) ||
                                SecurityLevelInterceptor.hackedResponseCache.containsKey(ownerKey)
                        if (hacked) {
                            val grantDescriptor = reply.readTypedObject(KeyDescriptor.CREATOR)
                            if (grantDescriptor?.domain == 2) {
                                grantedCertKeys[grantDescriptor.nspace] = ownerKey
                                Logger.i("Tracked GRANT nspace=${grantDescriptor.nspace} -> owner=$ownerKey uid=$callingUid")
                            }
                        }
                    }
                } catch (e: Exception) {
                    Logger.e("grantTransaction onPostTransact failed uid=$callingUid", e)
                }
            }
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
                val isGrant = reqDescriptor?.domain == 2 /* GRANT */
                // Resolve the cache key: GRANT reads map back to the owner; otherwise uid+alias.
                val cacheKey: SecurityLevelInterceptor.Key? = when {
                    isGrant -> reqDescriptor?.let { grantedCertKeys[it.nspace] }
                    reqDescriptor?.alias != null ->
                        SecurityLevelInterceptor.Key(callingUid, reqDescriptor.alias)
                    else -> null
                }
                // Act for target apps, isolated GMS workers, or tracked GRANT reads only.
                val trackedGrant = isGrant && cacheKey != null
                if (!trackedGrant && !PkgConfig.needHack(callingUid) &&
                    !PkgConfig.needGenerate(callingUid) && !isIsolatedUid(callingUid)) {
                    p.recycle()
                    return Skip
                }
                val response = reply.readTypedObject(KeyEntryResponse.CREATOR)
                if (response != null) {
                    // Cache-hit: return byte-for-byte identical cert produced earlier.
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

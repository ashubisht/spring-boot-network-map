package io.nmap.repository

import net.corda.core.crypto.SecureHash
import net.corda.nodeapi.internal.SignedNodeInfo

interface NodeInfoRepository {
    fun persistSignedNodeInfo(signedNodeInfo: SignedNodeInfo)
    fun getSignedNodeInfo(hash: String): Pair<SignedNodeInfo, ByteArray>?
    fun getAllHashes(): Collection<SecureHash>
    fun purgeAllPersistedSignedNodeInfos(): Int
}
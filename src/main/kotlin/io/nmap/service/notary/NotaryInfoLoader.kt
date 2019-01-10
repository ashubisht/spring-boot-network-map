package io.nmap.service.notary

import net.corda.core.node.NotaryInfo


interface NotaryInfoLoader {
    fun load(): List<NotaryInfo>
}
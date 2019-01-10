package io.nmap.controller.interfacer

import io.nmap.constants.AppConstants
import io.nmap.service.certificate.CertificateService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController
import java.lang.Exception
import javax.security.auth.x500.X500Principal

@RestController
class NetworkInterfacer (
        @Autowired private val certificateService: CertificateService
){

    //@PostMapping(path = ["/register-node"], consumes = [MediaType.APPLICATION_JSON_VALUE])
    @GetMapping(path = ["/register-node"])
    fun registerNode(name: String): String {

        val orgName = AppConstants.PARTY_NAME_PREFIX + name + AppConstants.PARTY_NAME_SUFFIX

        try{
            println(orgName)
            val partyX500Principal = X500Principal(orgName)

            certificateService.buildNodeCertificateStores(partyX500Principal)

            return "OK"
        }catch(e: Exception){
            e.printStackTrace()

            println( System.lineSeparator() + orgName)
            return "NOT OK"
        }
    }

}
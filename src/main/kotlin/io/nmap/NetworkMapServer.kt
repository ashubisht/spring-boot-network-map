package io.nmap

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication

@SpringBootApplication
open class NetworkMapServer

fun main(args: Array<String>) {
    SpringApplication.run(NetworkMapServer::class.java, *args)
}
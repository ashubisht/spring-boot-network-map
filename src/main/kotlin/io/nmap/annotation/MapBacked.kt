package io.nmap.annotation

import org.springframework.beans.factory.annotation.Qualifier

@Target(AnnotationTarget.CLASS, AnnotationTarget.VALUE_PARAMETER)
@Qualifier
annotation class MapBacked
# ProGuard rules for BioLink
# Keep Ktor & kotlinx.serialization
-keep class io.ktor.** { *; }
-keep class kotlinx.serialization.** { *; }
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt

# Keep ZXing
-keep class com.google.zxing.** { *; }
-keep class com.journeyapps.** { *; }

# Suppress R8 warnings for Java SE classes referenced by Ktor's IntelliJ debug detector
# (java.lang.management is not available on Android)
-dontwarn java.lang.management.ManagementFactory
-dontwarn java.lang.management.RuntimeMXBean

# Suppress R8 warnings for SLF4J static binder (pulled in transitively by Ktor)
-dontwarn org.slf4j.impl.StaticLoggerBinder

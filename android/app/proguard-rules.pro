# HorseSafe release (R8). A-13: geen logging in de release-build.

# android.util.Log volledig strippen (ook de argumentopbouw wordt dan dode code).
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
    public static int wtf(...);
    public static int println(...);
    public static java.lang.String getStackTraceString(java.lang.Throwable);
}

# Geen stacktraces naar stderr/logcat.
-assumenosideeffects class java.lang.Throwable {
    public void printStackTrace();
}

# yubikit: reflectie/serialisatie (moshi in fido) — volledig behouden.
-keep class com.yubico.yubikit.** { *; }
-keepclassmembers class com.yubico.yubikit.** { *; }

# slf4j-api zonder provider (bewust: NOP-logger, A-13). Waarschuwingen over de ontbrekende
# provider/static binder onderdrukken.
-dontwarn org.slf4j.**
-dontwarn com.squareup.moshi.**
# Compile-only annotatie in yubikit (SpotBugs); niet aanwezig op runtime.
-dontwarn edu.umd.cs.findbugs.annotations.**

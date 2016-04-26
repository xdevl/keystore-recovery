# Android keystore password recovery

This repository contains the sources of a simple Java based program to brute force a Java keystore in order to retrieve a lost key password. This application doesn't take any entry which means you will need to recompile it each time you want to change a parameter (see below to know how to do so). Hopefully this shouldn't be a problem because if you are reading this you probably already have a JDK all setup !
For more details about this program, see [How to recover a lost Android keystore password](http://xdevl.com/blog/index.php/java/how-to-recover-a-lost-android-keystore-password)

# Configuration

Before to start you will more likely want to configure a few things. All the configuration is done via static variables you will find at the beginning of Main.java:

- `sKeyStoreFile`: Absolute path to the keystore file to brute force
- `sAlias`: The key alias you want to brute force the password of (if none, the first one found will be used)
- `sThreadNum`: The number of threads you want to use to do the attack (if none, will be defaulted to the number of core of your machine)
- `sMinusCaseLetters, sUpperCaseLetters, sNumbers, sSymbols`: Default sets of symbols to use, feel free to change them as you want (ie: the less the better)
- `sWords`: A list of words your password may contains


# Compilation

You will need to have a local Gradle distribution installed in order to compile and run this application, no Gradle wrapper is actually provided.
To compile and launch the application just run the following:

```markdown
gradle run
```

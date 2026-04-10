# Maven Auto Certificate Generator Plugin

[![Maven](https://badges.mvnrepository.com/badge/com.github.yadickson/autocert/badge.svg?label=Maven)](https://mvnrepository.com/artifact/com.github.yadickson/autocert)
![version](https://img.shields.io/endpoint?style=flat-square&url=https%3A%2F%2Fgist.githubusercontent.com%2Fyadickson%2Fcdde25b73dd583aa4209d97f440c4abd%2Fraw%2Fautocert-version.json)
[![build](https://img.shields.io/github/actions/workflow/status/yadickson/autocert/ci.yml?branch=main&style=flat-square)](https://github.com/yadickson/autocert/actions/workflows/ci.yml)
![tests](https://img.shields.io/endpoint?style=flat-square&url=https%3A%2F%2Fgist.githubusercontent.com%2Fyadickson%2Fcdde25b73dd583aa4209d97f440c4abd%2Fraw%2Fautocert-junit-tests.json)
![coverage](https://img.shields.io/endpoint?style=flat-square&url=https%3A%2F%2Fgist.githubusercontent.com%2Fyadickson%2Fcdde25b73dd583aa4209d97f440c4abd%2Fraw%2Fautocert-cobertura-coverage.json)


Maven plugin to generate certificate resources in compilation time.

## POM properties

```xml
<properties>
    <maven.compiler.source>1.7</maven.compiler.source>
    <maven.compiler.target>1.7</maven.compiler.target>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
</properties>
```

## POM plugin config

```xml
<plugin>
    <groupId>com.github.yadickson</groupId>
    <artifactId>autocert</artifactId>
    <version>...</version>
    <executions>
        <execution>
            <goals>
                <goal>generator</goal>
            </goals>
        </execution>
    </executions>
    <configuration>
        <pubFile>...</pubFile>
        <keyFile>...</keyFile>
        <certFile>...</certFile>
        <algorithm>...</algorithm>
        <signature>...</signature>
        <keySize>...</keySize>
        <years>...</years>
        <issuer>...</issuer>
        <subject>...</subject>
        <directoryName>...</directoryName>
        <outputDirectory>...</outputDirectory>
    </configuration>
</plugin>
```

### pubFile (default: pub.pem)

```
Public file name.
```

### keyFile (default: key.pem)

```
Private file name.
```


### certFile (default: cert.pem)

```
Certificate file name.
```

### algorithm (default: RSA)

```
RSA
EC
ECDSA
ECDH
```

### signature (default: SHA256withRSA)

```
SHA256withRSA
SHA256withECDSA
```

### keySize (default: 1024)

```
RSA [1024, 2048, 4096, ..]
EC, ECDSA, ECDH [256, 384, 521]
```

### years (default: 10)

Years validation time

```
>= 1
```

### issuer (default: domain)

```
Issuer DN
```

### subject (default: main)

```
Subject DN
```

### directoryName (default: keys)

```
Directory name inside of outputDirectory.
```

### outputDirectory (default: ${project.build.directory}/generated-resources)

```
Resource output directory folder.
```

## Command line support
```
$ mvn clean package -Dautocert.pubFile=... -Dautocert.keyFile=... -Dautocert.certFile=... -Dautocert.algorithm=... -Dautocert.signature=... -Dautocert.keySize=... -Dautocert.years=... -Dautocert.issuer=... -Dautocert.subject=... -Dautocert.directoryName=... -Dautocert.outputDirectory=...
```

License
-------

GPL-3.0 © [Yadickson Soto](https://github.com/yadickson)

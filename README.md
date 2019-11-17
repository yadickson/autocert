# Maven Auto Certificate Generator Plugin

[![TravisCI Status][travis-image]][travis-url]
[![Codecov Status][codecov-image]][codecov-url]
[![Central OSSRH][oss-nexus-image]][oss-nexus-url]
[![Central Maven][central-image]][central-url]

Maven plugin to generate certificate resources in compilation time.

## POM properties

```xml
<properties>
    <maven.compiler.source>1.6</maven.compiler.source>
    <maven.compiler.target>1.6</maven.compiler.target>
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
            <configuration>
                <pubFile>...</pubFile>
                <keyFile>...</keyFile>
                <certFile>...</certFile>
                <algorithm>...</algorithm>
                <signature>...</signature>
                <keySize>...</keySize>
                <years>...</years>
                <issuerDN>...</issuerDN>
                <subjectDN>...</subjectDN>
                <directory>...</directory>
                <outputDirectory>...</outputDirectory>
            </configuration>
        </execution>
    </executions>
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

### issuerDN (default: cn=domain)

```
Issuer DN
```

### subjectDN (default: cn=main)

```
Subject DN
```

### directory (default: keys)

```
Resource directory folder.
```

### outputDirectory (default: ${project.build.directory}/generated-resources)

```
Resource output directory folder.
```

## Command line support
```
$ mvn clean package -Dautocert.pubFile=... -Dautocert.keyFile=... -Dautocert.certFile=... -Dautocert.algorithm=... -Dautocert.signature=... -Dautocert.keySize=... -Dautocert.years=... -Dautocert.issuerDN=... -Dautocert.subjectDN=... -Dautocert.directory=...
```

License
-------

GPL-3.0 © [Yadickson Soto](https://github.com/yadickson)

[travis-image]: https://travis-ci.org/yadickson/autocert.svg?branch=master
[travis-url]: https://travis-ci.org/yadickson/autocert

[codecov-image]: https://codecov.io/gh/yadickson/autocert/branch/master/graph/badge.svg?branch=master
[codecov-url]: https://codecov.io/gh/yadickson/autocert

[oss-nexus-image]: https://img.shields.io/nexus/r/https/oss.sonatype.org/com.github.yadickson/autocert.svg
[oss-nexus-url]: https://oss.sonatype.org/#nexus-search;quick~autocert

[central-image]: https://maven-badges.herokuapp.com/maven-central/com.github.yadickson/autocert/badge.svg
[central-url]: https://maven-badges.herokuapp.com/maven-central/com.github.yadickson/autocert

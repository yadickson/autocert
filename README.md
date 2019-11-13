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
                <certFile>...</certFile>
                <keyFile>...</keyFile>
                <algorithm>...</algorithm>
                <signature>...</signature>
                <keySize>...</keySize>
                <yearsValidity>...</yearsValidity>
            </configuration>
        </execution>
    </executions>
</plugin>
```

## algorithm

```
RSA
EC
ECDSA
ECDH
```

## signature

```
SHA256withRSA
SHA256withECDSA
```

## keySize

```
RSA [1024, 2048, 4096, ..]
EC, ECDSA, ECDH [256, 384, 521]
```

## yearsValidity

```
>= 1
```

[travis-image]: https://travis-ci.org/yadickson/autocert.svg?branch=master
[travis-url]: https://travis-ci.org/yadickson/autocert

[codecov-image]: https://codecov.io/gh/yadickson/autocert/branch/master/graph/badge.svg?branch=master
[codecov-url]: https://codecov.io/gh/yadickson/autocert

[oss-nexus-image]: https://img.shields.io/nexus/r/https/oss.sonatype.org/com.github.yadickson/autocert.svg
[oss-nexus-url]: https://oss.sonatype.org/#nexus-search;quick~autocert

[central-image]: https://maven-badges.herokuapp.com/maven-central/com.github.yadickson/autocert/badge.svg
[central-url]: https://maven-badges.herokuapp.com/maven-central/com.github.yadickson/autocert

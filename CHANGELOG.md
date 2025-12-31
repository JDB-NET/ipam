# Changelog

## [1.10.0](https://github.com/JDB-NET/ipam/compare/v1.9.1...v1.10.0) (2025-12-31)


### Features

* :sparkles: feature flags ([c1b0a70](https://github.com/JDB-NET/ipam/commit/c1b0a7084b7de1c476d588b9b71db0c267051c59))

## [1.9.1](https://github.com/JDB-NET/ipam/compare/v1.9.0...v1.9.1) (2025-12-29)


### Bug Fixes

* :bug: device page dictionary ([83c1b21](https://github.com/JDB-NET/ipam/commit/83c1b21c04163e22c25831ee8064f3cd5ea2c99d))

## [1.9.0](https://github.com/JDB-NET/ipam/compare/v1.8.0...v1.9.0) (2025-12-27)


### Features

* :sparkles: api rate limiting ([e316a16](https://github.com/JDB-NET/ipam/commit/e316a1638661e023a23b4b164fc2c773cd2f7e2a))
* :sparkles: custom fields by device or subnet ([b23cda4](https://github.com/JDB-NET/ipam/commit/b23cda48af575b92a16be2c211e2b2ebb9008a56))
* :sparkles: ip address history ([21042b7](https://github.com/JDB-NET/ipam/commit/21042b7fd701ecf025ba6d9407137d05156d884a))
* :sparkles: ip address notes/descriptions ([8b001a0](https://github.com/JDB-NET/ipam/commit/8b001a047b263501300213d40a474b19e976cabb))
* :sparkles: log api usage to audit log ([e028f96](https://github.com/JDB-NET/ipam/commit/e028f9610cb09c5551594a32fada43e7078a2a73))
* :sparkles: two factor authentication ([5037c1b](https://github.com/JDB-NET/ipam/commit/5037c1b57823a59ed4dfda6dc3a16d570cde47bd))
* :sparkles: vlan management ([c7350ae](https://github.com/JDB-NET/ipam/commit/c7350aeb1f5b3ac471e40a351c66f9a82b70bdf4))


### Bug Fixes

* :bug: 2fa verification ([53dc19a](https://github.com/JDB-NET/ipam/commit/53dc19a549ca4255d22cc9812c6e7e83e1b76697))


### Refactoring

* :art: auto save custom fields ([7e1c4b1](https://github.com/JDB-NET/ipam/commit/7e1c4b126e0d45010b17af7be64f31c85e33d76d))
* :art: minify ([9106799](https://github.com/JDB-NET/ipam/commit/91067994bac7688b95e8c71a69b14967f640407e))


### Style Changes

* :lipstick: backup code button ([181e2b2](https://github.com/JDB-NET/ipam/commit/181e2b2ca53b2c7b99899f54bef028a3d9ac30eb))

## [1.8.0](https://github.com/JDB-NET/ipam/compare/v1.7.0...v1.8.0) (2025-12-23)


### Features

* :sparkles: get next available ip by api ([64ae4be](https://github.com/JDB-NET/ipam/commit/64ae4be6d5997ff0b16ff5232237d38f2fec5b64))


### Bug Fixes

* :bug: global search missing from devices ([283c445](https://github.com/JDB-NET/ipam/commit/283c445263b7dc992448d907e682e53b7720b610))


### Build System

* :rocket: redeploy ([d7fcffd](https://github.com/JDB-NET/ipam/commit/d7fcffd4b5598b682dede864ba526b1257584f6a))

## [1.7.0](https://github.com/JDB-NET/ipam/compare/v1.6.1...v1.7.0) (2025-12-05)


### Features

* :sparkles: add devices by tag page ([9c0e6d0](https://github.com/JDB-NET/ipam/commit/9c0e6d035c8dda68281b2bfe2b7a61802353f7a7))


### Bug Fixes

* :bug: invalidate cache when device type is added ([47208b3](https://github.com/JDB-NET/ipam/commit/47208b31eed51f0cf0d7c8c411093bda1c84cf1b))
* :bug: invalidate linked cache ([8242e9d](https://github.com/JDB-NET/ipam/commit/8242e9d758ef19030b516e4a51f0cfb556f4e5ba))

## [1.6.1](https://github.com/JDB-NET/ipam/compare/v1.6.0...v1.6.1) (2025-12-05)


### Bug Fixes

* :bug: invalidate subnet cache when device is deleted ([286bf4b](https://github.com/JDB-NET/ipam/commit/286bf4b665e6352dea7b14753f080fa5cabb7926))

## [1.6.0](https://github.com/JDB-NET/ipam/compare/v1.5.1...v1.6.0) (2025-12-05)


### Features

* :sparkles: backup and restore ([707846b](https://github.com/JDB-NET/ipam/commit/707846bb3c717df9223ea7103e29efc6e671e16d))
* :sparkles: bulk operations ([2163be8](https://github.com/JDB-NET/ipam/commit/2163be8f79b579e38944a689915a18d5c35f8d3a))
* :sparkles: global search ([3e8965d](https://github.com/JDB-NET/ipam/commit/3e8965de6f19b3b382e236b08df685401205f356))
* :sparkles: in memory cache ([3a9250f](https://github.com/JDB-NET/ipam/commit/3a9250f5b0c14bfc6a807fe2948bbc852a652047))
* :sparkles: subnet utilisation stats ([f98e92d](https://github.com/JDB-NET/ipam/commit/f98e92da062640d47bec3516def0efde3aebd058))
* :sparkles: update available notification ([730b870](https://github.com/JDB-NET/ipam/commit/730b8701db81f5e03760a25209baeab2f81116fa))


### Refactoring

* :art: database indexing and optimisation ([47f68fd](https://github.com/JDB-NET/ipam/commit/47f68fd27cf62d0e0d2af55089bc0556043c12ff))
* :art: header link to github releases ([61e3200](https://github.com/JDB-NET/ipam/commit/61e320020724e437d8a607e7341b12b2fe6f794d))
* :art: improved audit log filtering ([f016598](https://github.com/JDB-NET/ipam/commit/f0165985fc194fd3a3e460b52447a5511908ed91))
* :art: js ([1d9209a](https://github.com/JDB-NET/ipam/commit/1d9209a714a6d0b7d1901b6e3470f5265e0171a6))
* :art: tidy nav bar ([69588d6](https://github.com/JDB-NET/ipam/commit/69588d6518571d8de55c718c14176bb78cb19ee1))


### CI/CD

* :rocket: include all commit types ([f6795f5](https://github.com/JDB-NET/ipam/commit/f6795f52815a2d599840c8ed83c99ad690a046c8))

## [1.5.1](https://github.com/JDB-NET/ipam/compare/v1.5.0...v1.5.1) (2025-12-04)


### Bug Fixes

* :bug: audit log on mobile ([6f01c99](https://github.com/JDB-NET/ipam/commit/6f01c9956f4a31414a082a779eb493735df0b8e6))

## [1.5.0](https://github.com/JDB-NET/ipam/compare/v1.4.2...v1.5.0) (2025-11-21)


### Features

* :sparkles: device tags ([ad1e576](https://github.com/JDB-NET/ipam/commit/ad1e576da42bf90c59347f7f7a4cce13c6842204))

## [1.4.2](https://github.com/JDB-NET/ipam/compare/v1.4.1...v1.4.2) (2025-11-08)


### Bug Fixes

* :bug: ensure all fields are updated by api ([5c1ad03](https://github.com/JDB-NET/ipam/commit/5c1ad039904b2c8c8629242b5558b03da5ad782c))

## [1.4.1](https://github.com/JDB-NET/ipam/compare/v1.4.0...v1.4.1) (2025-11-06)


### Bug Fixes

* :bug: pagination no longer gets out of control ([80b6de3](https://github.com/JDB-NET/ipam/commit/80b6de395fc4ddb4e7cd3ece89b423af2667d298))
* :bug: styling of admin and users pages ([d56e064](https://github.com/JDB-NET/ipam/commit/d56e0647f74fba1db1f504e02364406691ede9f3))

## [1.4.0](https://github.com/JDB-NET/ipam/compare/v1.3.0...v1.4.0) (2025-11-06)


### Features

* :sparkles: full api integration ([c53472c](https://github.com/JDB-NET/ipam/commit/c53472c5d760e28e53a737cb0546e85c9a422d15))

## [1.3.0](https://github.com/JDB-NET/ipam/compare/v1.2.0...v1.3.0) (2025-11-06)


### Features

* :sparkles: role based access control ([3bf2697](https://github.com/JDB-NET/ipam/commit/3bf269701030bc1f14a48c5af488286c424dbfa7))

## [1.2.0](https://github.com/JDB-NET/ipam/compare/v1.1.1...v1.2.0) (2025-11-06)


### Features

* :sparkles: added the ability to create/edit/remove device types ([d68eefc](https://github.com/JDB-NET/ipam/commit/d68eefcf0cc4a59cda9cedb3e126d974ee45d2ad))


### Bug Fixes

* :bug: missing button classes ([f93fa15](https://github.com/JDB-NET/ipam/commit/f93fa155eb5d6c9ff4ed19f332c3ad6fff328d31))

## [1.1.1](https://github.com/JDB-NET/ipam/compare/v1.1.0...v1.1.1) (2025-11-01)


### Bug Fixes

* :bug: image name ([de123fa](https://github.com/JDB-NET/ipam/commit/de123fafd40d97ea6e545bd8dd1d3a812e2a709f))

## [1.1.0](https://github.com/JDB-NET/ipam/compare/v1.0.0...v1.1.0) (2025-11-01)


### Features

* Added icon on login button. Closes [#1](https://github.com/JDB-NET/ipam/issues/1) ([6e068b6](https://github.com/JDB-NET/ipam/commit/6e068b672592f7d23ca66a0a6189b5763d89a698))
* Added light mode up to admin ([38c8402](https://github.com/JDB-NET/ipam/commit/38c840251f03c8f1e1a2c407efa77621df70ce2f))
* Rack stuff now complete ([5d220d3](https://github.com/JDB-NET/ipam/commit/5d220d354df83db8b2bfbf8e2c87bd78ba91f6e5))


### Bug Fixes

* Back buttons now hidden on mobile ([40a7a2f](https://github.com/JDB-NET/ipam/commit/40a7a2f2d58f6c89a7e7e74908c088e7eddf966a))
* Corrected image in deployment ([9ecd492](https://github.com/JDB-NET/ipam/commit/9ecd492065fcd226d274f8e343d401437e1c8de8))
* Fixed back button on device page ([9734e4d](https://github.com/JDB-NET/ipam/commit/9734e4df0b27461867393c132991f9e2ec907de4))
* Fixed database initialisation and dropped to 1 worker ([7cd6a0f](https://github.com/JDB-NET/ipam/commit/7cd6a0f96d8dc20743603d55498d8c1af8069690))

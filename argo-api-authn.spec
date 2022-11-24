#debuginfo not supported with Go
%global debug_package %{nil}

Name: argo-api-authn
Summary: ARGO Authentication API. Map X509, OICD to token.
Version: 1.1.0
Release: 1%{?dist}
License: ASL 2.0
Buildroot: %{_tmppath}/%{name}-buildroot
Group: Unspecified
Source0: %{name}-%{version}.tar.gz
BuildRequires: golang
BuildRequires: git
Requires(pre): /usr/sbin/useradd, /usr/bin/getent
ExcludeArch: i386

%description
Installs the ARGO Authentication API

%pre
/usr/bin/getent group argo-api-authn || /usr/sbin/groupadd -r argo-api-authn
/usr/bin/getent passwd argo-api-authn || /usr/sbin/useradd -r -s /sbin/nologin -d /var/www/argo-api-authn -g argo-api-authn argo-api-authn

%prep
%setup

%build
export GOPATH=$PWD
export PATH=$PATH:$GOPATH/bin

cd src/github.com/ARGOeu/argo-api-authn/
go install

%install
%{__rm} -rf %{buildroot}
install --directory %{buildroot}/var/www/argo-api-authn
install --mode 755 bin/argo-api-authn %{buildroot}/var/www/argo-api-authn/argo-api-authn

install --directory %{buildroot}/etc/argo-api-authn
install --directory %{buildroot}/etc/argo-api-authn/conf.d
install --mode 644 src/github.com/ARGOeu/argo-api-authn/conf/argo-api-authn-config.template %{buildroot}/etc/argo-api-authn/conf.d/argo-api-authn-config.json

install --directory %{buildroot}/usr/lib/systemd/system
install --mode 644 src/github.com/ARGOeu/argo-api-authn/argo-api-authn.service %{buildroot}/usr/lib/systemd/system/

%clean
%{__rm} -rf %{buildroot}
export GOPATH=$PWD
cd src/github.com/ARGOeu/argo-api-authn/
go clean

%files
%defattr(0644,argo-api-authn,argo-api-authn)
%attr(0750,argo-api-authn,argo-api-authn) /var/www/argo-api-authn
%attr(0755,argo-api-authn,argo-api-authn) /var/www/argo-api-authn/argo-api-authn
%config(noreplace) %attr(0644,argo-api-authn,argo-api-authn) /etc/argo-api-authn/conf.d/argo-api-authn-config.json
%attr(0644,root,root) /usr/lib/systemd/system/argo-api-authn.service

%changelog
* Tue Sep 26 2023 Agelos Tsalapatis  <agelos.tsal@gmail.com> - 1.1.0-1%{?dist}
- Release of argo-api-authn version 1.1.0
* Mon Oct 10 2022 Agelos Tsalapatis  <agelos.tsal@gmail.com> - 1.0.0-1%{?dist}
- Release of argo-api-authn version 1.0.0
* Mon Nov 8 2021 Agelos Tsalapatis  <agelos.tsal@gmail.com> - 0.1.8-1%{?dist}
- Release of argo-api-authn version 0.1.8
* Tue Apr 13 2021 Agelos Tsalapatis  <agelos.tsal@gmail.com> - 0.1.7-1%{?dist}
- Release of argo-api-authn version 0.1.7
* Wed Mar 31 2021 Agelos Tsalapatis  <agelos.tsal@gmail.com> - 0.1.6-1%{?dist}
- Release of argo-api-authn version 0.1.6
* Wed Nov 18 2020 Agelos Tsalapatis  <agelos.tsal@gmail.com> - 0.1.5-1%{?dist}
- Release of argo-api-authn version 0.1.5
* Thu Jun 13 2019 Agelos Tsalapatis  <agelos.tsal@gmail.com> - 0.1.4-1%{?dist}
- Release of argo-api-authn version 0.1.4
* Thu Jun 13 2019 Agelos Tsalapatis  <agelos.tsal@gmail.com> - 0.1.3-1%{?dist}
- ARGO-1773 Update authn scripts to filter service endpoints before creating the respective user
- ARGO-1615 update authn scripts to get site-mail from gocdb
- ARGO-1738 Add support for interacting with the argo-web-api
- ARGO-1737 Add support for headers auth method
- ARGO-1740 Change binding structure to be more generic
* Thu Mar 7 2019 Agelos Tsalapatis  <agelos.tsal@gmail.com> - 0.1.2-1%{?dist}
- ARGO-1659 Authn should not start if there is no database connection established
- Utility script that creates users and topics per site
- ARGO-1463 argo-api-authn moderate severity security vulnerability regarding requests library
* Tue Oct 2 2018 Kostas Koumantaros  <kkoumantaros@gmail.com> - 0.1.1-1%{?dist}
- ARGO-1405 Don't override the topic's acl in goc db users creation script
- ARGO-1397 Fix DN parsing to follow a predictable pattern
- ARGO-1168 Auth Service Initialisation
- ARGO-1171 Database Interface with some basic functionality
- ARGO-1172 Add functionality for required struct tags and convert stru… …
- ARGO-1173 Generic Handlers and Routing
- ARGO-1174 API CALL - Create Service
- ARGO-1176 API CALL - Get service(s)
- ARGO-1183 API CALL - Get Auth method(s)
- ARGO-1182 API CALL - Create Auth method
- ARGO-1217 Change service to service type
- ARGO-1184 API AuthN: Service types - use uuid
- ARGO-1205 API AuthN: Authentication method - use uuid
- ARGO-1211 API CALL - Create Binding
- ARGO-1212 API CALL - Get binding(s)
- ARGO-1222 List all auth methods bug fix
- ARGO-1123 List all service types bug fix
- ARGO-1165 X509 API Call
- ARGO-1227 Refactor Create Binding to also assign a UUID
- ARGO-1228 Refactor Get Binding(s) to work with UUID
- ARGO-1121 Script for creating users
- ARGO-1213 API CALL - Update Binding
- ARGO-1248 - create ARGO-api spec file
- ARGO-1214 API CALL - Delete Binding
- ARGO-1124 Better documentation and errors for - ARGO-authN service types
- ARGO-1220 Refactor errors to not expose go struct info
- ARGO-1189 API Call - Update Service Type
- ARGO-1191 API CALL - Delete Auth Method
- ARGO-1191 API CALL - Delete Auth Method
- ARGO-1272 Extend RDNSequence to string method to support DC rdn
- ARGO-1254 Service build and management fixes
- ARGO-1237 Add SysLogHandler
- ARGO-1280 Check Revocation List
- ARGO-1283 Check certificate expiration date
- ARGO-1284 Certificate verify hostname
- ARGO-1306 Update authn service file to include syslog name for the se… …
- ARGO-1293 Deprecate existing auth_methods package and its uses
- ARGO-1301 Refactor service-type - Add an additional field named type
- ARGO-1280 Check Revocation List
- ARGO-1283 Check certificate expiration date
- ARGO-1301 Refactor service-type - Add an additional field named type
- ARGO-1293 Deprecate existing auth_methods package and its uses
- ARGO-1301 Refactor service-type - Add an additional field named type
- ARGO-1304 Refactor service-types - remove field retrieval field
- ARGO-1305 Refactor datastore to deal with the new version of auth met… …
- ARGO-1311 Refactor utils method GetFieldValueByName to also work with… …
- ARGO-1312 Add utils method that sets a value to field given its name
- ARGO-1294 Refactor Create auth method using structs instead of generi… …
- ARGO-1295 Refactor Get auth method(s) using structs instead of generi… …
- ARGO-1206 API CALL - Update Auth method
- ARGO-1323 Ability to set up the service without cert verification
- ARGO-1300 Refactor x509 mapping to use the new auth method interface
- ARGO-1190 API CALL - Delete Service-type
- ARGO-1297 Remove deprecated package auth_methods and its uses
- ARGO-1362 Databse Session Clone functionality
- ARGO-1363 Check for unsupported auth type for the service type during… …
* Thu Jun 14 2018 Themis Zamani  <themiszamani@gmail.com> - 0.1.0-1%{?dist}
- Initial release

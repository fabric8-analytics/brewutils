%if 0%{?fedora}
%global _with_python3 1
%else
%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print (get_python_lib())")}
%endif

%global srcname brewutils

Name:           python-%{srcname}
Version:        1.0.2
Release:        2%{?dist}
Summary:        Brew Utilities CLI

License:        ASL 2.0
URL:            https://github.com/fabric8-analytics/brewutils
Source0:        brewutils-%{version}.tar.gz

BuildArch:      noarch


%description
%{summary}.

%package -n python2-%{srcname}
Summary:        %{summary}

%if 0%{?rhel}
BuildRequires:  python-devel
BuildRequires:  python-setuptools
Requires:       python-devel
%else
%{?python_provide:%python_provide python2-%{srcname}}
BuildRequires:  python2-devel
Requires:       python2-devel
%endif
Requires:       nodejs-packaging
Requires:       rpmdevtools
Requires:       redhat-rpm-config
Requires:       rpm-build
Requires:       koji
# python-requests >= 2.7.0 ?
Requires:       python-requests
Requires:       python-jsonschema
Requires:       python-unidiff


%description -n python2-%{srcname}
%{summary}.

Python 2 version.

# There's no Python 3 version because koji is still Python 2 only.

%prep
%autosetup -n %{srcname}-%{version}

%build
%py2_build

%install
%py2_install

%check
#PYTHONPATH=. %{__python} -c "import brewutils"

%files -n python2-%{srcname}
%{python2_sitelib}/%{srcname}-*.egg-info/
%{python2_sitelib}/%{srcname}/
%{_bindir}/brew-utils-cli


%changelog
* Thu Apr 27 2017 Jiri Popelka <jpopelka@redhat.com> - 1.0.2-2
- Explicitly requires setuptools for epel

* Fri Dec 09 2016 Nick Coghlan <ncoghlan@redhat.com> - 1.0.2-1
- fix import error that was breaking patch analysis

* Tue Nov 29 2016 Slavek Kabrda <bkabrda@redhat.com> - 1.0.1-1
- updated to version 1.0.1

* Tue Sep 20 2016 Jiri Popelka <jpopelka@redhat.com> - 1.0.0-2
- use macros
- python2-brewutils subpackage

* Mon Sep 19 2016 Pavel Odvody <podvody@redhat.com> - 1.0.0-1
- new version

from brewutils import Archive, SchemaRef, compare_version, compute_digest, cwd, download_file, schemas, tempdir
from glob import glob
from jsonschema import ValidationError
from koji import ClientSession, PathInfo
from logging import getLogger
from os import getenv, listdir, mkdir, devnull
from os.path import basename, dirname, isdir, join as join_path, relpath
from shutil import move
from subprocess import CalledProcessError, PIPE, Popen, check_call, check_output
from unidiff import PatchSet

logging = getLogger(__file__)


BREWHUB_URL = getenv('BREWHUB_URL', 'http://brewhub.devel.redhat.com/brewhub')
BREWPATH_URL = getenv('BREWPATH_URL', 'http://download.lab.bos.redhat.com/brewroot')


brew = ClientSession(BREWHUB_URL)
brew_path_url = PathInfo(BREWPATH_URL)


class BrewError(Exception):
    @staticmethod
    def from_error(old_error, message):
        be = BrewError(message)
        be.__cause__ = old_error


def sole_directory(root, items):
    """
    Check if the directory contains just one sub directory

    :param root:
    :param items:
    :return:
    """
    if len(items) == 1:
        if isdir(join_path(root, items[0])):
            return True

    return False


def walk_down(p):
    """
    Walk down from p until path with more than one non-directory child node is found

    :param p:
    :return:
    """
    root, suffix = '', ''
    while not root:
        vr = join_path(p, suffix)
        in_dir = listdir(vr)
        if sole_directory(vr, in_dir):
            suffix = in_dir.pop()
        else:
            root = vr

    return root


def find_common_root(vanilla, processed):
    """
    Find lowest common sub-nodes between two directory trees

    :param vanilla:
    :param processed:
    :return:
    """

    vanilla_root = walk_down(vanilla)
    vanilla_list = listdir(vanilla_root)

    processed_root = walk_down(processed)
    processed_list = listdir(processed_root)

    if set(processed_list) != set(vanilla_list):
        # not a match in top-level directory, try to walk down one level
        for candidate in processed_list:
            c = join_path(processed_root, candidate)

            # skip non directories
            if not isdir(c):
                continue

            # check again
            candidate_list = listdir(c)
            if set(candidate_list) == set(vanilla_list):
                processed_root = c
                break

    return vanilla_root, processed_root


class PackageBuilder(object):
    """
    PackageBuilder performs a preparation of package build environment and
    executes the actual build steps necessary for obtaining patch information
    """
    def __init__(self, pkg, buildroot, artifact):
        self._pkg = pkg
        self._buildroot = buildroot
        self._artifact_sha256 = artifact
        self._vanilla = None
        self._processed = None

    @property
    def artifact_sha256(self):
        return self._artifact_sha256

    @property
    def vanilla_root(self):
        return self._vanilla

    @property
    def processed_root(self):
        return self._processed

    @property
    def package(self):
        return self._pkg

    @property
    def buildroot(self):
        return self._buildroot

    def prepare_buildroots(self):
        """
        Prepares both `vanilla` and `processed` build roots

        `vanilla` buildroot is populated from sources extracted from the SRPM (Source0)
        `processed` buildroot is populated by executing rpmbuild with `-rp` flags to execute  rpmbuild
        until after the patch step
        """
        vanilla = join_path(self.buildroot, "vanilla")
        processed = join_path(self.buildroot, "processed")
        try:
            mkdir(vanilla)
            mkdir(processed)
        except OSError as exc:
            raise BrewError.from_error(exc, "Unable to prepare buildroot at {path}".format(path=self.buildroot))

        # Inspect `SourceX` directives in the spec file, then iterate through each of the sources
        # and find which of the source has same hash as the upstream archive. If no hash match is found
        # then take Source0.
        spec, source_files = self.package.get_source_files()
        if len(source_files) == 0:
            raise BrewError("No source files available")
        source_map = {compute_digest(t): t for t in source_files}
        if self.artifact_sha256 in source_map:
            source = source_map[self.artifact_sha256]
        else:
            source = source_files[0]

        # Extract the sources into vanilla
        Archive.extract(source, vanilla)

        # Move the contents of the source rpm to the processed directory
        # where we are going to execute the build
        with cwd(self.buildroot):
            for p in listdir(self.buildroot):
                if p not in ('vanilla', 'processed', basename(self.package.path)):
                    move(p, processed)

        with open(devnull, 'w') as null:
            # Execute RPM build in the processed directory
            check_call(["rpmbuild",
                        "--nodeps",
                        "--define", "_sourcedir " + processed,
                        "--define", "_specdir " + processed,
                        "--define", "_srcrpmdir " + processed,
                        "--define", "_rpmdir " + processed,
                        "--define", "_builddir " + processed,
                        # define py3dir so that it doesn't point to `pwd`
                        "--define", "py3dir /tmp/py3",
                        "-rp", self.package.path], stderr=null, stdout=null)

        # Find common root nodes between vanilla and processed directories and return them
        v, p = find_common_root(vanilla, processed)
        self._vanilla = v
        self._processed = p

    def diff_buildroots(self):
        """
        Performs a diff of the two build roots returning patch statistics

        :return: (int, int, list), (files_changed, lines_changed, diff_list)
        """

        self.prepare_buildroots()

        def __process_unidiff(diff):
            """ Process Unidiff's representation into simple dictionaries """
            changes = []
            for change in diff:
                mods = []
                for hunk in change:
                    mods.append(str(hunk))
                changes.append({'file': relpath(change.path, self.vanilla_root), 'lines': mods})

            return changes

        def __count_changes(data):
            """ Count the number of changed lines/files in the output diff """
            f, c = 0, 0
            for line in data:
                if line in ('-', '+') or line.startswith(('- ', '+ ')):
                    c += 1
                if line.startswith("@@"):
                    f += 1
            return f, c

        try:
            check_output(["diff", "-ur", self.vanilla_root, self.processed_root])
        except CalledProcessError as cpe:
            # when a difference between the two roots is found, the `diff` tool
            # returns 1 and the diff contents are printed to stdout, so we catch & swallow
            # the exception here
            if cpe.returncode != 1:
                raise BrewError.from_error(cpe, "Error diffing build roots")

            files, lines = __count_changes(cpe.output.splitlines())
            return files, lines, __process_unidiff(PatchSet(cpe.output.splitlines()))
        else:
            return 0, 0, []


class BrewRPMPackage(object):
    def __init__(self, brew_build):
        self._brew_build = brew_build
        self._path = None
        self._extracted = False

    @property
    def extracted(self):
        return self._extracted

    @property
    def path(self):
        return self._path

    @property
    def brew_build(self):
        return self._brew_build

    def download(self, target_dir, name=None):
        """
        Downloads the SRPM into `target_dir` as `name` or uses the retrieved file name

        :param target_dir: str
        :param name: str
        :return: str, path to the downloaded artifact
        """
        self._path = download_file(self.brew_build.srpm_url, target_dir, name=name)
        return self.path

    def extract_into(self, target_dir):
        """
        Extract the SRPM package using rpm2cpio / cpio into `target_dir`

        :param target_dir: str
        """
        if not self.path:
            return

        try:
            with cwd(target_dir):
                # More clean way of doing
                #
                #     rpm2cpio PKG | cpio -idm
                #
                rpm2cpio = Popen(["rpm2cpio", self.path], stdout=PIPE, stderr=PIPE)
                cpio = Popen(["cpio", "-idm"], stdin=rpm2cpio.stdout, stdout=PIPE, stderr=PIPE)
                rpm2cpio.stdout.close()
                cpio.communicate()
                self._extracted = cpio.returncode == 0
        except CalledProcessError as cpe:
            raise BrewError.from_error(cpe, "Unable to extract {pkg} into {path}".format(pkg=self.path,
                                                                                         path=target_dir))

    def fetch_sources_into(self, target_dir):
        """
        Convenience function combining download and extract steps

        :param target_dir: str
        :return: bool
        """
        if self.download(target_dir):
            self.extract_into(target_dir)
            return True
        else:
            return False

    def get_source_files(self):
        """
        Gets the Specfile and all referenced SourceX files

        :return: (str, List[str]), (spec_path, source_paths)
        """
        if not self.path or not self._extracted:
            raise BrewError("Unknown path to package")

        pattern = join_path(dirname(self.path), "*.spec")
        specs = glob(pattern)
        if len(specs) != 1:  # sanity
            raise BrewError("Invalid number of specfiles ({num}) in {path}".format(num=len(specs),
                                                                                   path=self.path))

        #
        # Source0: http://pypi.python.org/packages/source/r/requests/requests-2.7.0.tar.gz
        #
        spec = specs.pop()
        files = []
        sources = check_output(["spectool", "-S", spec]).splitlines()
        for src in sources:
            name, url = src.split(" ", 1)
            files.append(join_path(dirname(self.path), basename(url)))

        return spec, files

    def get_patch_files(self):
        """
        Gets all *.patch files

        :return: List[str]
        """
        if not self.path or not self.extracted:
            raise BrewError("Unknown path to package")

        pattern = join_path(dirname(self.path), "*.patch")
        return [basename(p) for p in glob(pattern)]


class BrewPackage(object):
    @schemas.input(SchemaRef("brew-package-search", "1-0-0"))
    def __init__(self, data, name_match=None):
        self._name = data['name']

        self._name_prefix = None
        self._name_suffix = None

        if name_match:
            offset = self._name.find(name_match)
            if offset > 0:
                self._name_prefix = self._name[:offset].strip('-')

            s = offset + len(name_match)
            if s < len(self._name) - 1:
                self._name_suffix = self._name[s:].strip('-')

        self._id = data['id']
        self._brew_object = data

    @property
    def name(self):
        return self._name

    @property
    def name_prefix(self):
        return self._name_prefix

    @property
    def name_suffix(self):
        return self._name_suffix

    @property
    def id(self):
        return self._id

    @property
    def brew_object(self):
        return self._brew_object

    @property
    def exact_match(self):
        """ If there are no suffixes or prefixes we have an exact match """
        return not (self.name_suffix or self.name_prefix)

    @staticmethod
    def find(name):
        """
        Searches Brew for the given package `name`

        :param name: str
        :return: PackageSearchResult
        """
        brew_data = brew.search('*{pkg}*'.format(pkg=name), "package", "glob")
        if not brew_data:
            return None

        return PackageSearchResult([BrewPackage(data, name)
                                   for data in brew_data])


class BuildStatus(object):
    (Pending, Complete, Deleted) = range(3)


class BrewBuild(object):
    # make sure to always return valid data
    default = {
        'diff': {
            "files": 0,
            "lines": 0,
            "changes": []
        },
        "patch_files": [],
        "package": ""
    }

    @schemas.input(SchemaRef("brew-build", "1-1-0"))
    def __init__(self, data, pkg):
        self._package = pkg
        self._brew_object = data
        self._version = data['version']
        self._id = data['build_id']
        self._release = data['release']
        self._epoch = data['epoch'] or 0
        self._srpm_url = None
        self._resolve_srpm_location()

    @property
    def nvr(self):
        epoch = ""
        if self._epoch:
            epoch = str(self._epoch) + ":"
        return "{e}{n}-{v}-{r}".format(e=epoch,
                                       n=self._package.name,
                                       v=self._version,
                                       r=self._release)

    @property
    def epoch(self):
        return self._epoch

    @property
    def version(self):
        return self._version

    @property
    def package(self):
        return self._package

    @property
    def id(self):
        return self._id

    @property
    def release(self):
        return self._release

    @property
    def srpm_url(self):
        return self._srpm_url

    def get_applied_patches(self, artifact):
        with tempdir() as tmp:
            package_name = "{name}-{version}-{release}".format(name=self.package.name,
                                                               version=self.version,
                                                               release=self.release)
            package = BrewRPMPackage(self)
            builder = PackageBuilder(package, tmp, artifact)
            if package.fetch_sources_into(tmp):
                patch_files = package.get_patch_files()
                changes = builder.diff_buildroots()
                if changes:
                    files, lines, data = changes
                    return {"diff": {"files": files, "lines": lines, "changes": data},
                            "patch_files": patch_files, "package": package_name}

        return self.default

    @staticmethod
    def get_for_package(pkg, version):
        """
        Retrieve all `BrewBuild` objects for given `pkg` and `version`

        :param pkg: BrewPackage
        :param version: str
        :return: List[BrewBuild]
        """
        if not pkg or not version:
            return None

        builds = []
        for build in brew.listBuilds(packageID=pkg.id, state=BuildStatus.Complete):
            if compare_version(build['version'], version) == 0:
                try:
                    # BrewBuild ctor raises when the build is in invalid state
                    # such as zero or more than one SRPMs
                    b = BrewBuild(build, pkg)
                    builds.append(b)
                except (BrewError, ValidationError) as exc:
                    logging.debug(exc)

        return builds

    def __repr__(self):
        return "[BrewBuild package={package_name}, version={version}-{release}, build_id={build_id}]".format(
            version=self.version, package_name=self.package.name, release=self.release, build_id=self.id)

    def _resolve_srpm_location(self):
        rpms = brew.listRPMs(self.id, arches=["src"])
        if len(rpms) != 1:  # sanity
            raise BrewError("Zero or multiple SRPMs for {self}".format(self=self))

        self._srpm_url = join_path(brew_path_url.build(self._brew_object), brew_path_url.rpm(rpms.pop()))
        return self._srpm_url


class PackageSearchResult(object):
    """
    PackageSearchResult object stores the result categorizes the input list of packages
    into two distinct groups:

    1) Exact match (single item)
    2) Fuzzy matches (multiple items)

    Convenience methods and properties are provided for getting the desired data
    """
    def __init__(self, items):
        self._exact = None
        self._fuzzy = []

        # detect exact/inexact matches
        for pkg in items:
            if pkg.exact_match:
                if self._exact:  # sanity
                    raise BrewError("More than one exact match for {pkg_name}".format(pkg_name=pkg.name))
                self._exact = pkg
            else:
                self._fuzzy.append(pkg)

        # sort fuzzy entries by the length of name prefix
        self._fuzzy.sort(key=lambda x: len(x.name_prefix) if x.name_prefix else 999)

    @property
    def exact(self):
        """ Returns a package with exact name match """
        return self._exact

    def with_suffix(self, suffix):
        """ Returns packages with given suffix """
        return [p for p in self._fuzzy if p.name_suffix == suffix]

    def with_prefix(self, prefix):
        """ Returns packages with given prefix """
        return [p for p in self._fuzzy if p.name_prefix == prefix]

    @property
    def inexact_shortest_prefix(self):
        """ Returns package with shortest prefix """
        return self._fuzzy[0] if self._fuzzy else None

    @property
    def best_name(self):
        """ Returns exact package match or match with shortest prefix """
        return self.exact or self.inexact_shortest_prefix

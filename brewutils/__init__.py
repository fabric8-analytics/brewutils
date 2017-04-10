from abc import ABCMeta, abstractmethod
from collections import OrderedDict, namedtuple
from contextlib import contextmanager
from functools import wraps
from json import loads as json_load_string
from jsonschema import validate as schema_validate
from logging import getLogger
from os import chdir, getcwd
from os.path import join as join_path
from pkgutil import get_data
from re import compile as regexp
from requests import get
from shutil import rmtree
from six import add_metaclass
from subprocess import CalledProcessError, check_output
from tempfile import mkdtemp


logger = getLogger(__name__)


@contextmanager
def cwd(target):
    "Manage cwd in a pushd/popd fashion"
    curdir= getcwd()
    chdir(target)
    try:
        yield
    finally:
        chdir(curdir)


@contextmanager
def tempdir():
    dirpath = mkdtemp()
    try:
        yield dirpath
    finally:
        rmtree(dirpath)


def compare_version(a, b):
    """
    Compare two version strings

    :param a: str
    :param b: str
    :return: -1 / 0 / 1
    """

    def _range(q):
        """
        Convert a version string to array of integers:
           "1.2.3" -> [1, 2, 3]

        :param q: str
        :return: List[int]
        """
        r = []
        for n in q.replace('-', '.').split('.'):
            try:
                r.append(int(n))
            except ValueError:
                # sort rc*, alpha, beta etc. lower than their non-annotated counterparts
                r.append(-1)
        return r

    def _append_zeros(x, num_zeros):
        """
        Append `num_zeros` zeros to a copy of `x` and return it

        :param x: List[int]
        :param num_zeros: int
        :return: List[int]
        """
        nx = list(x)
        for _ in range(num_zeros):
            nx.append(0)
        return nx

    def _cardinal(x, y):
        """
        Make both input lists be of same cardinality

        :param x: List[int]
        :param y: List[int]
        :return: List[int]
        """
        lx, ly = len(x), len(y)
        if lx == ly:
            return x, y
        elif lx > ly:
            return x, _append_zeros(y, lx - ly)
        else:
            return _append_zeros(x, ly - lx), y

    left, right = _cardinal(_range(a), _range(b))

    return (left > right) - (left < right)


def compute_digest(target, function='sha256', raise_on_error=False):
    """
    compute digest of a provided file

    :param target: str, file path
    :param function: str, prefix name of the hashing function
    :param raise_on_error: bool, raise an error when computation wasn't successful if set to True
    :returns str or None, computed digest

    `function` requires an executable with matching name on the system (sha256sum, sha1sum etc.)
    """
    function += 'sum'
    # returns e.g.:
    # 65ecde5d025fcf57ceaa32230e2ff884ab204065b86e0e34e609313c7bdc7b47  /etc/passwd
    data = get_command_output([function, target], graceful=not raise_on_error)
    try:
        return data[0].split(' ')[0].strip()
    except IndexError:
        logger.error("unable to compute digest of %r, likely it doesn't exist or is a directory",
                     target)
        if raise_on_error:
            raise RuntimeError("can't compute digest of %s" % target)


def get_command_output(args, graceful=True, is_json=False):
    """
    improved version of subprocess.check_output

    :param graceful: bool, if False, raise Exception when command fails
    :param is_json: bool, if True, return decoded json

    :return: list of strings, output which command emitted
    """
    logger.debug("running command %s", args)
    try:
        # Using universal_newlines mostly for the side-effect of decoding
        # the output as UTF-8 text on Python 3.x
        out = check_output(args, universal_newlines=True)
    except CalledProcessError as ex:
        # TODO: we may want to use subprocess.Popen to be able to also print stderr here
        #  (while not mixing it with stdout that is returned if the subprocess succeeds)
        logger.warning("command %s ended with %s\n%s", args, ex.returncode, ex.output)
        if not graceful:
            logger.error("exception is fatal")
            raise Exception("Error during running command %s: %r" % (args, ex.output))
        return []
    else:
        if is_json:
            # FIXME: some error handling here would be great
            return json_load_string(out)
        else:
            return [f for f in out.split('\n') if f]  # py2 & 3 compat

def download_file(url, target_dir=None, name=None):
    local_filename = name or url.split('/')[-1]

    logger.debug("fetching artifact from: %s", url)
    if target_dir:
        local_filename = join_path(target_dir, local_filename)

    r = get(url, stream=True)
    if r.status_code == 404:
        logger.error("unable to download: %s", url)
        return None

    with open(local_filename, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)
    logger.debug("artifact location: %s", local_filename)

    return local_filename


class Archive(object):
    "Extract different kind of archives"
    TarMatcher = regexp('\.tar\..{1,3}$')

    @staticmethod
    def extract(target, dest):
        "Detects archive type and extracts it"
        tar = Archive.TarMatcher.search(target)
        if target.endswith(('.zip', '.whl', '.jar')):
            return Archive.extract_zip(target, dest)
        elif tar or target.endswith(('.tgz', '.bz2')):
            return Archive.extract_tar(target, dest)
        else:
            raise ValueError('Unknown archive for {0}'.format(target))

    @staticmethod
    def extract_zip(target, dest):
        get_command_output(['unzip', '-d', dest, target])

    @staticmethod
    def extract_tar(target, dest):
        get_command_output(['tar', 'xf', target, '-C', dest])


class SchemaRef(namedtuple("SchemaRef", "name version")):
    """Name and version number for a JSON schema"""
    __slots__ = ()  # 3.4.3 compatibility: prevent __dict__ override

    def __str__(self):
        return "{} v{}".format(self.name, self.version)

    # Define new schema versions based on this one
    def _split_version_info(self):
        return tuple(map(int, self.version.split("-")))

    def _replace_version_info(self, model, revision, addition):
        version = "-".join(map(str, (model, revision, addition)))
        return self._replace(version=version)

    def next_addition(self):
        model, revision, addition = self._split_version_info()
        return self._replace_version_info(model, revision, addition+1)

    def next_revision(self):
        model, revision, addition = self._split_version_info()
        return self._replace_version_info(model, revision+1, addition)

    def next_model(self):
        model, revision, addition = self._split_version_info()
        return self._replace_version_info(model+1, revision, addition)


class SchemaLookupError(LookupError):
    """Failed to find requested schema in schema library"""
    def __init__(self, schema_ref):
        self.schema_ref = schema_ref

    def __str__(self):
        return "Unknown schema: {}".format(self.schema_ref)


@add_metaclass(ABCMeta)
class AbstractSchemaLibrary(object):
    def load_schema(self, schema_ref):
        """Loads and parses specified schema from the library"""
        try:
            schema_data = self.read_binary_schema(schema_ref)
        except Exception as exc:
            # Py2 compatibility: switch to "from exc" once workers are on Py3
            new_exc = SchemaLookupError(schema_ref)
            new_exc.__cause__ = exc
            raise new_exc
        return json_load_string(schema_data.decode("utf-8"), object_pairs_hook=OrderedDict)

    @abstractmethod
    def read_binary_schema(self, schema_ref):
        """Reads raw binary schema from path constructed from given schema ref"""
        raise NotImplementedError('read_binary_schema is abstract method')


class SchemaLibrary(AbstractSchemaLibrary):
    """Load named and versioned JSON schemas"""
    def __init__(self, schema_dir):
        # Py2 compatibility: use explicit super()
        super(SchemaLibrary, self).__init__()
        self.schema_dir = schema_dir
        self._schema_pattern = join_path(schema_dir, "{}-v{}.schema.json")

    def read_binary_schema(self, schema_ref):
        schema_path = self._schema_pattern.format(*schema_ref)
        with open(schema_path, "rb") as schema_file:
            return schema_file.read()


class BundledSchemaLibrary(SchemaLibrary):
    """Load named and version JSON schemas bundled with a Python package"""
    def __init__(self, schema_dir, base_module):
        # Py2 compatibility: use explicit super()
        super(BundledSchemaLibrary, self).__init__(schema_dir)
        self.base_module = base_module

    def read_binary_schema(self, schema_ref):
        schema_path = self._schema_pattern.format(*schema_ref)
        return get_data(self.base_module, schema_path)


class SchemaValidator(object):
    """
    SchemaValidator encapsulates the provided schema library
    and provides pre/post-condition checking decorators

    >>> schema = SchemaValidator(someSchemaLibrary)

    Pre-condition - input check
    ---------------------------
    The first dictionary parameter of the function is validated against
    the provided schema

    Example:
        >>> @schema.input(SchemaRef("some-schema", "v1"))
        >>> def somefunc(data):
        >>>    pass


    Post-condition - result check
    -----------------------------
    The return value of the function is validated against the provided schema

    Example:
        >>> @schema.result(SchemaRef("some-result-schema", "v1"))
        >>> def somefunc(data):
        >>>    return {'foo': 'bar'}

    """
    def __init__(self, library):
        self._schema_cache = {}
        self._library = library

    def _ensure_schema(self, name):
        if name not in self._schema_cache:
            self._schema_cache[name] = self._library.load_schema(name)

        return self._schema_cache[name]

    def input(self, *args):
        def decorator(func):
            """ Inner function decorator """
            @wraps(func)
            def wrapper(*largs, **kwargs):
                s = self._ensure_schema(args[0])
                arg = None
                # find first dict argument, hack so that the same decorator
                # works for functions as well as for methods
                for a in largs:
                    if isinstance(a, dict):
                        arg = a
                        break
                schema_validate(arg, s)
                return func(*largs, **kwargs)
            return wrapper
        return decorator

    def result(self, *args):
        def decorator(func):
            """ Inner function decorator """
            @wraps(func)
            def wrapper(*largs, **kwargs):
                s = self._ensure_schema(args[0])
                r = func(*largs, **kwargs)
                schema_validate(r, s)
                return r
            return wrapper
        return decorator


schemas = SchemaValidator(BundledSchemaLibrary('schemas', __name__))
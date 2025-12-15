# -*- coding: utf-8 -*-

import json
import os
import threading
import traceback
import re
import time

from com.pnfsoftware.jeb.client.api import IScript
from com.pnfsoftware.jeb.core import Artifact, RuntimeProjectUtil
from com.pnfsoftware.jeb.core.actions import (
    ActionContext,
    ActionOverridesData,
    Actions,
    ActionXrefsData,
)
from com.pnfsoftware.jeb.core.input import FileInput
from com.pnfsoftware.jeb.core.output.text import TextDocumentUtil
from com.pnfsoftware.jeb.core.units.code.android import IApkUnit
from com.pnfsoftware.jeb.core.util import DecompilerHelper
from java.io import File

# Python 2.7 changes - use urlparse from urlparse module instead of urllib.parse
from urlparse import urlparse

# Python 2.7 doesn't have typing, so we'll define our own minimal substitutes
# and ignore most type annotations


# Mock typing classes/functions for type annotation compatibility
class Any(object):
    pass


class Callable(object):
    pass


def get_type_hints(func):
    """Mock for get_type_hints that works with Python 2.7 functions"""
    hints = {}

    # Try to get annotations (modern Python way)
    if hasattr(func, "__annotations__"):
        hints.update(getattr(func, "__annotations__", {}))

    # For Python 2.7, inspect the function signature
    import inspect

    args, varargs, keywords, defaults = inspect.getargspec(func)

    # Add all positional parameters with Any type
    for arg in args:
        if arg not in hints:
            hints[arg] = Any

    return hints


class TypedDict(dict):
    pass


class Optional(object):
    pass


class Annotated(object):
    pass


class TypeVar(object):
    pass


class Generic(object):
    pass


# Use BaseHTTPServer instead of http.server
import BaseHTTPServer


class JSONRPCError(Exception):
    def __init__(self, code, message, data=None):
        Exception.__init__(self, message)
        self.code = code
        self.message = message
        self.data = data


class RPCRegistry(object):
    def __init__(self):
        self.methods = {}

    def register(self, func):
        self.methods[func.__name__] = func
        return func

    def dispatch(self, method, params):
        if method not in self.methods:
            raise JSONRPCError(-32601, "Method '{0}' not found".format(method))

        func = self.methods[method]
        hints = get_type_hints(func)

        # Remove return annotation if present
        if "return" in hints:
            hints.pop("return", None)

        if isinstance(params, list):
            if len(params) != len(hints):
                raise JSONRPCError(
                    -32602,
                    "Invalid params: expected {0} arguments, got {1}".format(
                        len(hints), len(params)
                    ),
                )

            # Python 2.7 doesn't support zip with items() directly
            # Convert to simpler validation approach
            converted_params = []
            param_items = hints.items()
            for i, value in enumerate(params):
                if i < len(param_items):
                    param_name, expected_type = param_items[i]
                    # In Python 2.7, we'll do minimal type checking
                    converted_params.append(value)
                else:
                    converted_params.append(value)

            return func(*converted_params)
        elif isinstance(params, dict):
            # Simplify type validation for Python 2.7
            if set(params.keys()) != set(hints.keys()):
                raise JSONRPCError(
                    -32602,
                    "Invalid params: expected {0}".format(list(hints.keys())),
                )

            # Validate and convert parameters
            converted_params = {}
            for param_name, expected_type in hints.items():
                value = params.get(param_name)
                # Skip detailed type validation in Python 2.7 version
                converted_params[param_name] = value

            return func(**converted_params)
        else:
            raise JSONRPCError(
                -32600, "Invalid Request: params must be array or object"
            )


rpc_registry = RPCRegistry()


def jsonrpc(func):
    """Decorator to register a function as a JSON-RPC method"""
    global rpc_registry
    return rpc_registry.register(func)


class JSONRPCRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def send_jsonrpc_error(self, code, message, id=None):
        response = {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
        }
        if id is not None:
            response["id"] = id
        response_body = json.dumps(response)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response_body))
        self.end_headers()
        self.wfile.write(response_body)

    def do_POST(self):
        global rpc_registry

        parsed_path = urlparse(self.path)
        if parsed_path.path != "/mcp":
            self.send_jsonrpc_error(-32098, "Invalid endpoint", None)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self.send_jsonrpc_error(-32700, "Parse error: missing request body", None)
            return

        request_body = self.rfile.read(content_length)
        try:
            request = json.loads(request_body)
        except ValueError:  # Python 2.7 uses ValueError instead of JSONDecodeError
            self.send_jsonrpc_error(-32700, "Parse error: invalid JSON", None)
            return

        # Prepare the response
        response = {
            "jsonrpc": "2.0"
        }
        if request.get("id") is not None:
            response["id"] = request.get("id")

        try:
            # Basic JSON-RPC validation
            if not isinstance(request, dict):
                raise JSONRPCError(-32600, "Invalid Request")
            if request.get("jsonrpc") != "2.0":
                raise JSONRPCError(-32600, "Invalid JSON-RPC version")
            if "method" not in request:
                raise JSONRPCError(-32600, "Method not specified")

            # Dispatch the method
            result = rpc_registry.dispatch(request["method"], request.get("params", []))
            response["result"] = result

        except JSONRPCError as e:
            response["error"] = {
                "code": e.code,
                "message": e.message
            }
            if e.data is not None:
                response["error"]["data"] = e.data
        except Exception as e:
            traceback.print_exc()
            response["error"] = {
                "code": -32603,
                "message": "Internal error (please report a bug)",
                "data": traceback.format_exc(),
            }

        try:
            response_body = json.dumps(response)
        except Exception as e:
            traceback.print_exc()
            response_body = json.dumps({
                "error": {
                    "code": -32603,
                    "message": "Internal error (please report a bug)",
                    "data": traceback.format_exc(),
                }
            })

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response_body))
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format, *args):
        # Suppress logging
        pass


class MCPHTTPServer(BaseHTTPServer.HTTPServer):
    allow_reuse_address = False


class Server(object):  # Use explicit inheritance from object for py2
    HOST = os.getenv("JEB_MCPC_HOST", "127.0.0.1")
    PORT = int(os.getenv("JEB_MCPC_PORT", "16161"))

    def __init__(self):
        self.server = None
        self.server_thread = None
        self.running = False

    def start(self):
        if self.running:
            print("[MCP] Server is already running")
            return

        # Python 2.7 doesn't support daemon parameter in Thread constructor
        self.server_thread = threading.Thread(target=self._run_server)
        self.server_thread.daemon = True  # Set daemon attribute after creation
        self.running = True
        self.server_thread.start()

    def stop(self):
        if not self.running:
            return

        self.running = False
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.server_thread:
            self.server_thread.join()
            self.server = None
        print("[MCP] Server stopped")

    def _run_server(self):
        try:
            # Create server in the thread to handle binding
            self.server = MCPHTTPServer((Server.HOST, Server.PORT), JSONRPCRequestHandler)
            print("[MCP] Server started at http://{0}:{1}".format(Server.HOST, Server.PORT))
            self.server.serve_forever()
        except OSError as e:
            if e.errno == 98 or e.errno == 10048:  # Port already in use (Linux/Windows)
                print("[MCP] Error: Port 13337 is already in use")
            else:
                print("[MCP] Server error: {0}".format(e))
            self.running = False
        except Exception as e:
            print("[MCP] Server error: {0}".format(e))
        finally:
            self.running = False


# 定义为 unicode 字符串 (u'...')
def preprocess_manifest_py2(manifest_text):
    """
    一个为 Python 2 设计的、健壮的 Manifest 预处理函数。
    它会清理非法字符，并强行移除所有 <meta-data> 标签以避免解析错误。
    """
    # 1. 确保输入是 unicode 字符串，并忽略解码错误
    if isinstance(manifest_text, str):
        try:
            manifest_text = manifest_text.decode('utf-8')
        except UnicodeDecodeError:
            manifest_text = manifest_text.decode('utf-8', 'ignore')

    # 2. 清理基本的非法 XML 字符
    # (保留这个作为基础卫生措施)
    cleaned_chars = []
    for char in manifest_text:
        codepoint = ord(char)
        if (codepoint == 0x9 or codepoint == 0xA or codepoint == 0xD or
           (codepoint >= 0x20 and codepoint <= 0xD7FF) or
           (codepoint >= 0xE000 and codepoint <= 0xFFFD) or
           (codepoint >= 0x10000 and codepoint <= 0x10FFFF)):
            cleaned_chars.append(char)
    text_no_illegal_chars = u"".join(cleaned_chars)

    # 3. 使用正则表达式，强行移除所有 <meta-data ... /> 标签
    # re.DOTALL 使得 '.' 可以匹配包括换行在内的任意字符
    # re.IGNORECASE 忽略大小写
    # ur'...' 定义一个 unicode 正则表达式
    text_no_metadata = re.sub(
        ur'<\s*meta-data.*?/>',
        u'',  # 替换为空字符串，即直接删除
        text_no_illegal_chars,
        flags=re.DOTALL | re.IGNORECASE
    )
    
    return text_no_metadata

@jsonrpc
def ping():
    """Do a simple ping to check server is alive and running"""
    return "pong"


# implement a FIFO queue to store the artifacts
artifactQueue = list()

def addArtifactToQueue(artifact):
    """Add an artifact to the queue"""
    artifactQueue.append(artifact)

def getArtifactFromQueue():
    """Get an artifact from the queue"""
    if len(artifactQueue) > 0:
        return artifactQueue.pop(0)
    return None

def clearArtifactQueue():
    """Clear the artifact queue"""
    global artifactQueue
    artifactQueue = list()

MAX_OPENED_ARTIFACTS = 1

# 全局缓存，目前只缓存了Mainfest文本和exported组件，加载新的apk文件时将被清除。
apk_cached_data = {}

def getOrLoadApk(filepath):
    if not os.path.exists(filepath):
        print("File not found: %s" % filepath)
        raise JSONRPCError(-1, ErrorMessages.LOAD_APK_NOT_FOUND)

    engctx = CTX.getEnginesContext()

    if not engctx:
        print('Back-end engines not initialized')
        raise JSONRPCError(-1, ErrorMessages.LOAD_APK_FAILED)

    # Create a project
    project = engctx.loadProject('MCPPluginProject')
    correspondingArtifact = None
    for artifact in project.getLiveArtifacts():
        if artifact.getArtifact().getName() == filepath:
            # If the artifact is already loaded, return it
            correspondingArtifact = artifact
            break
    if not correspondingArtifact:
        # try to load the artifact, but first check if the queue size has been exceeded
        if len(artifactQueue) >= MAX_OPENED_ARTIFACTS:
            # unload the oldest artifact
            oldestArtifact = getArtifactFromQueue()
            if oldestArtifact:
                # unload the artifact
                oldestArtifactName = oldestArtifact.getArtifact().getName()
                print('Unloading artifact: %s because queue size limit exeeded' % oldestArtifactName)
                RuntimeProjectUtil.destroyLiveArtifact(oldestArtifact)

        # Fix: 直接用filepath而不是basename作为Artifact的名称，否则如果加载了多个同名不同路径的apk，会出现问题。
        correspondingArtifact = project.processArtifact(Artifact(filepath, FileInput(File(filepath))))
        addArtifactToQueue(correspondingArtifact)
        apk_cached_data.clear()
    
    unit = correspondingArtifact.getMainUnit()
    if isinstance(unit, IApkUnit):
        # If the unit is already loaded, return it
        return unit    
    raise JSONRPCError(-1, ErrorMessages.LOAD_APK_FAILED)


@jsonrpc
def get_manifest(filepath):
    """Get the manifest of the given APK file in path, note filepath needs to be an absolute path"""
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)  # Fixed: use getOrLoadApk function to load the APK
    
    if 'manifest' in apk_cached_data:
        return apk_cached_data['manifest']
    
    man = apk.getManifest()
    if man is None:
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)
    
    doc = man.getFormatter().getPresentation(0).getDocument()
    text = TextDocumentUtil.getText(doc)
    #engctx.unloadProjects(True)
    apk_cached_data['manifest'] = text
    return text


@jsonrpc
def get_all_exported_activities(filepath):
    """
    Get all exported Activity components from the APK and normalize their class names.

    An Activity is considered "exported" if:
    - It explicitly sets android:exported="true", or
    - It omits android:exported but includes an <intent-filter> (implicitly exported)

    Note:
    - If android:exported="false" is explicitly set, the Activity is NOT exported, even if it has intent-filters.

    Class name normalization rules:
    - If it starts with '.', prepend the package name (e.g., .MainActivity -> com.example.app.MainActivity)
    - If it has no '.', include both the original and package-prefixed versions
    - If it's a full class name, keep as-is

    Returns a list of fully qualified exported Activity class names (for use in decompilation, etc.)
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)
    
    from xml.etree import ElementTree as ET

    manifest_text = get_manifest(filepath)
    manifest_text = preprocess_manifest_py2(manifest_text)

    if not manifest_text:
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)
    
    # 首先尝试在缓存中取，跳过XML解析。
    if 'exported_activities' in apk_cached_data:
        return apk_cached_data['exported_activities']

    try:
        root = ET.fromstring(manifest_text.encode('utf-8'))
    except Exception as e:
        print("[MCP] Error parsing manifest:", e)
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)

    ANDROID_NS = 'http://schemas.android.com/apk/res/android'
    exported_activities = []

    # 获取包名
    package_name = root.attrib.get('package', '').strip()

    # 查找 <application> 节点
    app_node = root.find('application')
    if app_node is None:
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)

    for activity in app_node.findall('activity'):
        name = activity.attrib.get('{' + ANDROID_NS + '}name')
        exported = activity.attrib.get('{' + ANDROID_NS + '}exported')
        has_intent_filter = len(activity.findall('intent-filter')) > 0

        if not name:
            continue

        if exported == "true" or (exported is None and has_intent_filter):
            normalized = set()

            if name.startswith('.'):
                normalized.add(package_name + name)
            elif '.' not in name:
                normalized.add(name)
                normalized.add(package_name + '.' + name)
            else:
                normalized.add(name)

            exported_activities.extend(normalized)
    # 缓存导出Activity数据
    apk_cached_data['exported_activities'] = exported_activities
    return exported_activities


@jsonrpc
def get_exported_services(filepath):
    """
    Get all exported Service components from the APK and normalize their class names.

    A Service is considered "exported" if:
    - It explicitly sets android:exported="true", or
    - It omits android:exported but includes an <intent-filter> (implicitly exported)

    Note:
    - If android:exported="false" is explicitly set, the Service is NOT exported, even if it has intent-filters.

    Class name normalization rules:
    - If it starts with '.', prepend the package name (e.g., .MainService -> com.example.app.MainService)
    - If it has no '.', include both the original and package-prefixed versions
    - If it's a full class name, keep as-is

    Returns a list of fully qualified exported Service class names (for use in decompilation, etc.)
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)
    
    from xml.etree import ElementTree as ET

    manifest_text = get_manifest(filepath)
    manifest_text = preprocess_manifest_py2(manifest_text)

    if not manifest_text:
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)
    
    # 首先尝试在缓存中取，跳过XML解析。
    if 'exported_services' in apk_cached_data:
        return apk_cached_data['exported_services']

    try:
        root = ET.fromstring(manifest_text.encode('utf-8'))
    except Exception as e:
        print("[MCP] Error parsing manifest:", e)
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)

    ANDROID_NS = 'http://schemas.android.com/apk/res/android'
    exported_services = []

    # 获取包名
    package_name = root.attrib.get('package', '').strip()

    # 查找 <application> 节点
    app_node = root.find('application')
    if app_node is None:
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)

    for activity in app_node.findall('service'):
        name = activity.attrib.get('{' + ANDROID_NS + '}name')
        exported = activity.attrib.get('{' + ANDROID_NS + '}exported')
        has_intent_filter = len(activity.findall('intent-filter')) > 0

        if not name:
            continue

        if exported == "true" or (exported is None and has_intent_filter):
            normalized = set()

            if name.startswith('.'):
                normalized.add(package_name + name)
            elif '.' not in name:
                normalized.add(name)
                normalized.add(package_name + '.' + name)
            else:
                normalized.add(name)

            exported_services.extend(normalized)
    # 缓存导出Service数据
    apk_cached_data['exported_services'] = exported_services
    return exported_services


@jsonrpc
def get_method_decompiled_code(filepath, method_signature):
    """Get the decompiled code of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    Dex units use Java-style internal addresses to identify items:
    - package: Lcom/abc/
    - type: Lcom/abc/Foo;
    - method: Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    - field: Lcom/abc/Foo;->flag1:Z
    note filepath needs to be an absolute path
    """
    if not filepath or not method_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    
    codeUnit = apk.getDex()
    method = codeUnit.getMethod(method_signature)
    decomp = DecompilerHelper.getDecompiler(codeUnit)
    if not decomp:
        print('Cannot acquire decompiler for unit: %s' % decomp)
        raise JSONRPCError(-1, ErrorMessages.DECOMPILE_FAILED)
    
    if method is None:
        print('Method not found: %s' % method_signature)
        raise_method_not_found(method_signature)

    if not decomp.decompileMethod(method.getSignature()):
        print('Failed decompiling method')
        raise JSONRPCError(-1, ErrorMessages.DECOMPILE_FAILED)

    text = decomp.getDecompiledMethodText(method.getSignature())
    return text


@jsonrpc
def get_method_smali_code(filepath, method_signature):
    """Get the smali code of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    Dex units use Java-style internal addresses to identify items:
    - package: Lcom/abc/
    - type: Lcom/abc/Foo;
    - method: Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    - field: Lcom/abc/Foo;->flag1:Z
    note filepath needs to be an absolute path
    """
    if not filepath or not method_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    
    codeUnit = apk.getDex()
    method = codeUnit.getMethod(method_signature)

    if method is None:
        print('Method not found: %s' % method_signature)
        raise_method_not_found(method_signature)
    
    instructions = get_method_instructions(method)
    smali_code = ""
    for instruction in instructions:
        smali_code = smali_code + instruction.format(None)  + "\n"

    return smali_code


@jsonrpc
def get_class_decompiled_code(filepath, class_signature):
    """Get the decompiled code of the given class in the APK file, the passed in class_signature needs to be a fully-qualified signature
    Dex units use Java-style internal addresses to identify items:
    - package: Lcom/abc/
    - type: Lcom/abc/Foo;
    - method: Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    - field: Lcom/abc/Foo;->flag1:Z
    note filepath needs to be an absolute path
    """
    if not filepath or not class_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    
    codeUnit = apk.getDex()
    clazz = codeUnit.getClass(class_signature)
    if clazz is None:
        print('Class not found: %s' % class_signature)
        raise_class_not_found(class_signature)

    decomp = DecompilerHelper.getDecompiler(codeUnit)
    if not decomp:
        print('Cannot acquire decompiler for unit: %s' % codeUnit)
        return ErrorMessages.DECOMPILE_FAILED

    if not decomp.decompileClass(clazz.getSignature()):
        print('Failed decompiling class: %s' % class_signature)
        return ErrorMessages.DECOMPILE_FAILED

    text = decomp.getDecompiledClassText(clazz.getSignature())
    return text


@jsonrpc
def get_method_callers(filepath, method_signature):
    """
    Get the callers of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    note filepath needs to be an absolute path
    """
    if not filepath or not method_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    
    ret = []
    codeUnit = apk.getDex()
    method = codeUnit.getMethod(method_signature)
    if method is None:
        print("Method not found: %s" % method_signature)
        raise_method_not_found(method_signature)
        
    actionXrefsData = ActionXrefsData()
    actionContext = ActionContext(codeUnit, Actions.QUERY_XREFS, method.getItemId(), None)
    if codeUnit.prepareExecution(actionContext,actionXrefsData):
        for i in range(actionXrefsData.getAddresses().size()):
            ret.append({
                "address": actionXrefsData.getAddresses()[i],
                "details": actionXrefsData.getDetails()[i]
            })
    return ret


@jsonrpc
def get_field_callers(filepath, field_signature):
    """
    Get the callers of the given field in the APK file, the passed in field_signature needs to be a fully-qualified signature
    note filepath needs to be an absolute path
    """
    if not filepath or not field_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    
    ret = []
    codeUnit = apk.getDex()
    field = codeUnit.getField(field_signature)
    if field is None:
        print("Field not found: %s" % field_signature)
        raise_field_not_found(field_signature)
        
    actionXrefsData = ActionXrefsData()
    actionContext = ActionContext(codeUnit, Actions.QUERY_XREFS, field.getItemId(), None)
    if codeUnit.prepareExecution(actionContext,actionXrefsData):
        for i in range(actionXrefsData.getAddresses().size()):
            ret.append({
                "address": actionXrefsData.getAddresses()[i],
                "details": actionXrefsData.getDetails()[i]
            })
    return ret


@jsonrpc
def get_method_overrides(filepath, method_signature):
    """
    Get the overrides of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    note filepath needs to be an absolute path
    """
    if not filepath or not method_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    
    ret = []
    codeUnit = apk.getDex()
    method = codeUnit.getMethod(method_signature)
    # FIXME: 
    # 当前如果method_signature在apk中没有任何使用super调用原函数的地方
    # 则这里无法获取到method导致后面拿不到QUERY_OVERRIDES
    # 需要解决这个问题。
    if method is None:
        print("Method not found: %s" % method_signature)
        raise_method_not_found(method_signature)
        
    data = ActionOverridesData()
    actionContext = ActionContext(codeUnit, Actions.QUERY_OVERRIDES, method.getItemId(), None)
    if codeUnit.prepareExecution(actionContext,data):
        for i in range(data.getAddresses().size()):
            ret.append(data.getAddresses()[i])
    return ret


@jsonrpc
def get_superclass(filepath, class_signature):
    """
    Get the superclass of the given class in the APK file, the passed in class_signature needs to be a fully-qualified signature
    the passed in filepath needs to be a fully-qualified absolute path
    """
    if not filepath or not class_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)
    
    apk = getOrLoadApk(filepath)

    codeUnit = apk.getDex()
    clazz = codeUnit.getClass(class_signature)
    if clazz is None:
        raise_class_not_found(class_signature)

    return clazz.getSupertypeSignature(True)


@jsonrpc
def get_interfaces(filepath, class_signature):
    """
    Get the interfaces of the given class in the APK file, the passed in class_signature needs to be a fully-qualified signature
    the passed in filepath needs to be a fully-qualified absolute path
    """
    if not filepath or not class_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)

    codeUnit = apk.getDex()
    clazz = codeUnit.getClass(class_signature)
    if clazz is None:
        print("Class not found: %s" % class_signature)
        raise_class_not_found(class_signature)
    
    interfaces = []
    interfaces_array = clazz.getInterfaceSignatures(True)
    for interface in interfaces_array:
        interfaces.append(interface)

    return interfaces


@jsonrpc
def get_class_methods(filepath, class_signature):
    """
    Get the methods of the given class in the APK file, the passed in class_signature needs to be a fully-qualified signature
    the passed in filepath needs to be a fully-qualified absolute path
    """
    if not filepath or not class_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)

    codeUnit = apk.getDex()
    clazz = codeUnit.getClass(class_signature)
    if clazz is None:
        print("Class not found: %s" % class_signature)
        raise_class_not_found(class_signature)
    
    method_signatures = []
    dex_methods = clazz.getMethods()
    for method in dex_methods:
        if method:
            method_signatures.append(method.getSignature(True))

    return method_signatures


@jsonrpc
def get_class_fields(filepath, class_signature):
    """
    Get the fields of the given class in the APK file, the passed in class_signature needs to be a fully-qualified signature
    the passed in filepath needs to be a fully-qualified absolute path
    """
    if not filepath or not class_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)

    codeUnit = apk.getDex()
    clazz = codeUnit.getClass(class_signature)
    if clazz is None:
        print("Class not found: %s" % class_signature)
        raise_class_not_found(class_signature)
    
    field_signatures = []
    dex_field = clazz.getFields()
    for field in dex_field:
        if field:
            field_signatures.append(field.getSignature(True))

    return field_signatures


@jsonrpc
def get_all_classes(filepath, offset, limit):
    """
    Get all class signatures in the APK file with pagination support.

    Args:
        filepath: The absolute path to the APK file
        offset: The starting index (0-based)
        limit: The maximum number of classes to return (0 means return all remaining)

    Returns:
        A dict containing:
        - classes: List of class signatures
        - total: Total number of classes
        - offset: The offset used
        - limit: The limit used
        - has_more: Whether there are more classes available
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    codeUnit = apk.getDex()

    all_classes = codeUnit.getClasses()
    total = len(all_classes)

    # Validate offset
    if offset < 0:
        offset = 0
    if offset >= total:
        return {
            "classes": [],
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": False
        }

    # Calculate end index
    if limit <= 0:
        end = total
    else:
        end = min(offset + limit, total)

    # Extract class signatures
    result_classes = []
    for i in range(offset, end):
        clazz = all_classes[i]
        result_classes.append(clazz.getSignature(True))

    return {
        "classes": result_classes,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": end < total
    }


@jsonrpc
def get_all_strings(filepath, offset, limit):
    """
    Get all strings in the APK file with pagination support.

    Args:
        filepath: The absolute path to the APK file
        offset: The starting index (0-based)
        limit: The maximum number of strings to return (0 means return all remaining)

    Returns:
        A dict containing:
        - strings: List of strings
        - total: Total number of strings
        - offset: The offset used
        - limit: The limit used
        - has_more: Whether there are more strings available
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    codeUnit = apk.getDex()

    all_strings = codeUnit.getStrings()
    total = len(all_strings)

    # Validate offset
    if offset < 0:
        offset = 0
    if offset >= total:
        return {
            "strings": [],
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": False
        }

    # Calculate end index
    if limit <= 0:
        end = total
    else:
        end = min(offset + limit, total)

    # Extract strings
    result_strings = []
    for i in range(offset, end):
        result_strings.append(all_strings[i])

    return {
        "strings": result_strings,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": end < total
    }


@jsonrpc
def search_classes(filepath, keyword):
    """
    Search for classes whose name contains the specified keyword.

    Args:
        filepath: The absolute path to the APK file
        keyword: The keyword to search for (case-insensitive)

    Returns:
        A list of matching class signatures
    """
    if not filepath or not keyword:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    codeUnit = apk.getDex()

    all_classes = codeUnit.getClasses()
    keyword_lower = keyword.lower()

    matching_classes = []
    for clazz in all_classes:
        class_sig = clazz.getSignature(True)
        if keyword_lower in class_sig.lower():
            matching_classes.append(class_sig)

    return matching_classes


@jsonrpc
def search_methods(filepath, keyword):
    """
    Search for methods whose signature contains the specified keyword.

    Args:
        filepath: The absolute path to the APK file
        keyword: The keyword to search for (case-insensitive)

    Returns:
        A list of matching method signatures
    """
    if not filepath or not keyword:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    codeUnit = apk.getDex()

    all_methods = codeUnit.getMethods()
    keyword_lower = keyword.lower()

    matching_methods = []
    for method in all_methods:
        method_sig = method.getSignature(True)
        if keyword_lower in method_sig.lower():
            matching_methods.append(method_sig)

    return matching_methods


@jsonrpc
def search_strings(filepath, keyword):
    """
    Search for strings that contain the specified keyword.

    Args:
        filepath: The absolute path to the APK file
        keyword: The keyword to search for (case-sensitive)

    Returns:
        A list of matching strings
    """
    if not filepath or not keyword:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    codeUnit = apk.getDex()

    all_strings = codeUnit.getStrings()

    matching_strings = []
    for string in all_strings:
        if keyword in string:
            matching_strings.append(string)

    return matching_strings


@jsonrpc
def find_string_usages(filepath, target_string):
    """
    Find all methods that reference the specified string.

    Args:
        filepath: The absolute path to the APK file
        target_string: The string to search for

    Returns:
        A list of dicts containing:
        - class_signature: The class containing the method
        - method_signature: The method that uses the string
    """
    if not filepath or target_string is None:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    codeUnit = apk.getDex()

    all_methods = codeUnit.getMethods()
    usages = []

    for method in all_methods:
        # Get method data
        data = method.getData()
        if data is None:
            continue

        # Check if method contains the target string
        instructions = get_method_instructions(method)
        if instructions is None:
            continue

        for instruction in instructions:
            # Check if instruction references a string
            instr_str = instruction.format(None)
            if target_string in instr_str:
                usages.append({
                    "class_signature": method.getClassType().getSignature(True),
                    "method_signature": method.getSignature(True)
                })
                break

    return usages


@jsonrpc
def get_main_activity(filepath):
    """
    Get the main activity class signature from AndroidManifest.xml.

    Args:
        filepath: The absolute path to the APK file

    Returns:
        The main activity class signature, or None if not found
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    from xml.etree import ElementTree as ET

    manifest_text = get_manifest(filepath)
    manifest_text = preprocess_manifest_py2(manifest_text)

    if not manifest_text:
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)

    try:
        root = ET.fromstring(manifest_text.encode('utf-8'))
    except Exception as e:
        print("[MCP] Error parsing manifest:", e)
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)

    ANDROID_NS = 'http://schemas.android.com/apk/res/android'
    package_name = root.attrib.get('package', '').strip()

    app_node = root.find('application')
    if app_node is None:
        return None

    # Find activity with MAIN action and LAUNCHER category
    for activity in app_node.findall('activity'):
        for intent_filter in activity.findall('intent-filter'):
            has_main = False
            has_launcher = False

            for action in intent_filter.findall('action'):
                action_name = action.attrib.get('{' + ANDROID_NS + '}name', '')
                if action_name == 'android.intent.action.MAIN':
                    has_main = True

            for category in intent_filter.findall('category'):
                category_name = category.attrib.get('{' + ANDROID_NS + '}name', '')
                if category_name == 'android.intent.category.LAUNCHER':
                    has_launcher = True

            if has_main and has_launcher:
                name = activity.attrib.get('{' + ANDROID_NS + '}name', '')
                if name:
                    # Normalize class name
                    if name.startswith('.'):
                        return 'L' + (package_name + name).replace('.', '/') + ';'
                    elif '.' not in name:
                        return 'L' + package_name.replace('.', '/') + '/' + name + ';'
                    else:
                        return 'L' + name.replace('.', '/') + ';'

    return None


@jsonrpc
def get_application_class(filepath):
    """
    Get the Application class signature from AndroidManifest.xml.

    Args:
        filepath: The absolute path to the APK file

    Returns:
        The Application class signature, or None if using default Application class
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    from xml.etree import ElementTree as ET

    manifest_text = get_manifest(filepath)
    manifest_text = preprocess_manifest_py2(manifest_text)

    if not manifest_text:
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)

    try:
        root = ET.fromstring(manifest_text.encode('utf-8'))
    except Exception as e:
        print("[MCP] Error parsing manifest:", e)
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)

    ANDROID_NS = 'http://schemas.android.com/apk/res/android'
    package_name = root.attrib.get('package', '').strip()

    app_node = root.find('application')
    if app_node is None:
        return None

    app_name = app_node.attrib.get('{' + ANDROID_NS + '}name', '')
    if not app_name:
        return None

    # Normalize class name
    if app_name.startswith('.'):
        return 'L' + (package_name + app_name).replace('.', '/') + ';'
    elif '.' not in app_name:
        return 'L' + package_name.replace('.', '/') + '/' + app_name + ';'
    else:
        return 'L' + app_name.replace('.', '/') + ';'


@jsonrpc
def rename_class_name(filepath, class_signature, new_class_name):
    if not filepath or not class_signature:
        return False

    apk = getOrLoadApk(filepath)
    if apk is None:
        return False

    codeUnit = apk.getDex()
    clazz = codeUnit.getClass(class_signature)
    if clazz is None:
        return False

    print("rename class:", clazz.getName(), "to", new_class_name)
    clazz.setName(new_class_name)
    return True


@jsonrpc
def get_classes_batch(filepath, class_signatures):
    """
    Batch get decompiled code for multiple classes.

    Args:
        filepath: The absolute path to the APK file
        class_signatures: List of class signatures to decompile

    Returns:
        A dict mapping class_signature to decompiled code (or error message)
    """
    if not filepath or not class_signatures:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    codeUnit = apk.getDex()
    decomp = DecompilerHelper.getDecompiler(codeUnit)

    if not decomp:
        raise JSONRPCError(-1, ErrorMessages.DECOMPILE_FAILED)

    result = {}
    for class_sig in class_signatures:
        try:
            clazz = codeUnit.getClass(class_sig)
            if clazz is None:
                result[class_sig] = "[Error] Class not found"
                continue

            if not decomp.decompileClass(clazz.getSignature()):
                result[class_sig] = "[Error] Decompilation failed"
                continue

            text = decomp.getDecompiledClassText(clazz.getSignature())
            result[class_sig] = text
        except Exception as e:
            result[class_sig] = "[Error] " + str(e)

    return result


def get_method_instructions(method):
    """
    Helper function to safely get instructions from a method using correct JEB API.

    Args:
        method: IDexMethod object

    Returns:
        List of instructions or None if method has no code
    """
    if not method.isInternal():
        return None

    data = method.getData()
    if data is None:
        return None

    code_item = data.getCodeItem()
    if code_item is None:
        return None

    return code_item.getInstructions()


@jsonrpc
def find_native_methods(filepath):
    """
    Find all native method declarations in the APK.

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A list of dicts containing:
        - class_signature: The class containing the native method
        - method_signature: The native method signature
        - method_name: The method name
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    codeUnit = apk.getDex()

    # Import IDexMethod to access FLAG_NATIVE
    from com.pnfsoftware.jeb.core.units.code.android.dex import IDexMethod

    all_methods = codeUnit.getMethods()
    native_methods = []

    for method in all_methods:
        # Check if method is native using flags (correct JEB API way)
        if (method.getGenericFlags() & IDexMethod.FLAG_NATIVE) != 0:
            native_methods.append({
                "class_signature": method.getClassType().getSignature(True),
                "method_signature": method.getSignature(True),
                "method_name": method.getName()
            })

    return native_methods


@jsonrpc
def find_reflection_calls(filepath):
    """
    Find all reflection API calls (Class.forName, getDeclaredMethod, invoke, etc.).

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A list of dicts containing:
        - class_signature: The class making the reflection call
        - method_signature: The method making the reflection call
        - reflection_type: Type of reflection (forName, getDeclaredMethod, invoke, etc.)
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    codeUnit = apk.getDex()

    # Reflection API patterns to search for
    reflection_patterns = [
        "Ljava/lang/Class;->forName",
        "Ljava/lang/Class;->getDeclaredMethod",
        "Ljava/lang/Class;->getMethod",
        "Ljava/lang/Class;->getDeclaredField",
        "Ljava/lang/Class;->getField",
        "Ljava/lang/reflect/Method;->invoke",
        "Ljava/lang/reflect/Field;->get",
        "Ljava/lang/reflect/Field;->set",
        "Ljava/lang/Class;->newInstance",
        "Ljava/lang/reflect/Constructor;->newInstance"
    ]

    all_methods = codeUnit.getMethods()
    reflection_calls = []

    for method in all_methods:
        # Check if method is internal (has implementation)
        if not method.isInternal():
            continue

        # Get method data and code item (correct JEB API way)
        data = method.getData()
        if data is None:
            continue

        code_item = data.getCodeItem()
        if code_item is None:
            continue

        instructions = code_item.getInstructions()
        if instructions is None:
            continue

        for instruction in instructions:
            instr_str = instruction.format(None)

            for pattern in reflection_patterns:
                if pattern in instr_str:
                    # Extract reflection type
                    reflection_type = pattern.split("->")[1] if "->" in pattern else "unknown"

                    reflection_calls.append({
                        "class_signature": method.getClassType().getSignature(True),
                        "method_signature": method.getSignature(True),
                        "reflection_type": reflection_type,
                        "instruction": instr_str
                    })
                    break

    return reflection_calls


@jsonrpc
def find_crypto_usage(filepath):
    """
    Find all cryptography API usage (Cipher, MessageDigest, SecretKey, etc.).

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A list of dicts containing:
        - class_signature: The class using crypto APIs
        - method_signature: The method using crypto APIs
        - crypto_api: The crypto API being used
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    codeUnit = apk.getDex()

    crypto_patterns = [
        "Ljavax/crypto/Cipher;",
        "Ljava/security/MessageDigest;",
        "Ljavax/crypto/SecretKey;",
        "Ljavax/crypto/KeyGenerator;",
        "Ljavax/crypto/spec/SecretKeySpec;",
        "Ljavax/crypto/spec/IvParameterSpec;",
        "Ljava/security/KeyPairGenerator;",
        "Ljava/security/SecureRandom;",
        "Ljavax/crypto/Mac;",
        "Ljava/security/Signature;",
        "Ljava/security/KeyStore;"
    ]

    all_methods = codeUnit.getMethods()
    crypto_usage = []

    for method in all_methods:
        instructions = get_method_instructions(method)
        if instructions is None:
            continue

        found_apis = set()
        for instruction in instructions:
            instr_str = instruction.format(None)

            for pattern in crypto_patterns:
                if pattern in instr_str:
                    found_apis.add(pattern)

        if found_apis:
            crypto_usage.append({
                "class_signature": method.getClassType().getSignature(True),
                "method_signature": method.getSignature(True),
                "crypto_apis": list(found_apis)
            })

    return crypto_usage


@jsonrpc
def find_network_usage(filepath):
    """
    Find all network API usage (HttpURLConnection, OkHttp, Socket, etc.).

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A list of dicts containing:
        - class_signature: The class using network APIs
        - method_signature: The method using network APIs
        - network_apis: List of network APIs being used
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    codeUnit = apk.getDex()

    network_patterns = [
        "Ljava/net/HttpURLConnection;",
        "Ljava/net/URL;",
        "Ljava/net/Socket;",
        "Ljava/net/ServerSocket;",
        "Lokhttp3/OkHttpClient;",
        "Lokhttp3/Request;",
        "Lokhttp3/Response;",
        "Lorg/apache/http/client/HttpClient;",
        "Lorg/apache/http/HttpResponse;",
        "Landroid/webkit/WebView;"
    ]

    all_methods = codeUnit.getMethods()
    network_usage = []

    for method in all_methods:
        instructions = get_method_instructions(method)
        if instructions is None:
            continue

        found_apis = set()
        for instruction in instructions:
            instr_str = instruction.format(None)

            for pattern in network_patterns:
                if pattern in instr_str:
                    found_apis.add(pattern)

        if found_apis:
            network_usage.append({
                "class_signature": method.getClassType().getSignature(True),
                "method_signature": method.getSignature(True),
                "network_apis": list(found_apis)
            })

    return network_usage


@jsonrpc
def find_file_operations(filepath):
    """
    Find all file operation API usage (File, FileInputStream, SharedPreferences, etc.).

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A list of dicts containing:
        - class_signature: The class performing file operations
        - method_signature: The method performing file operations
        - file_apis: List of file APIs being used
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    codeUnit = apk.getDex()

    file_patterns = [
        "Ljava/io/File;",
        "Ljava/io/FileInputStream;",
        "Ljava/io/FileOutputStream;",
        "Ljava/io/FileReader;",
        "Ljava/io/FileWriter;",
        "Ljava/io/RandomAccessFile;",
        "Landroid/content/SharedPreferences;",
        "Landroid/database/sqlite/SQLiteDatabase;",
        "Ljava/io/BufferedReader;",
        "Ljava/io/BufferedWriter;"
    ]

    all_methods = codeUnit.getMethods()
    file_usage = []

    for method in all_methods:
        instructions = get_method_instructions(method)

        if instructions is None:

            continue

        found_apis = set()
        for instruction in instructions:
            instr_str = instruction.format(None)

            for pattern in file_patterns:
                if pattern in instr_str:
                    found_apis.add(pattern)

        if found_apis:
            file_usage.append({
                "class_signature": method.getClassType().getSignature(True),
                "method_signature": method.getSignature(True),
                "file_apis": list(found_apis)
            })

    return file_usage


@jsonrpc
def find_dynamic_loading(filepath):
    """
    Find all dynamic code loading (DexClassLoader, PathClassLoader, etc.).

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A list of dicts containing:
        - class_signature: The class performing dynamic loading
        - method_signature: The method performing dynamic loading
        - loader_type: Type of class loader being used
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    codeUnit = apk.getDex()

    loader_patterns = [
        "Ldalvik/system/DexClassLoader;",
        "Ldalvik/system/PathClassLoader;",
        "Ldalvik/system/InMemoryDexClassLoader;",
        "Ldalvik/system/DexFile;",
        "Ljava/lang/ClassLoader;->loadClass"
    ]

    all_methods = codeUnit.getMethods()
    dynamic_loading = []

    for method in all_methods:
        instructions = get_method_instructions(method)

        if instructions is None:

            continue

        for instruction in instructions:
            instr_str = instruction.format(None)

            for pattern in loader_patterns:
                if pattern in instr_str:
                    dynamic_loading.append({
                        "class_signature": method.getClassType().getSignature(True),
                        "method_signature": method.getSignature(True),
                        "loader_type": pattern,
                        "instruction": instr_str
                    })
                    break

    return dynamic_loading


@jsonrpc
def get_method_callees(filepath, method_signature):
    """
    Get all methods called by the given method (callees).

    Args:
        filepath: The absolute path to the APK file
        method_signature: The method signature to analyze

    Returns:
        A list of method signatures that are called by this method
    """
    if not filepath or not method_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    codeUnit = apk.getDex()

    method = codeUnit.getMethod(method_signature)
    if method is None:
        raise_method_not_found(method_signature)

    callees = []
    instructions = get_method_instructions(method)
    if instructions is None:
        return callees

    for instruction in instructions:
        instr_str = instruction.format(None)

        # Look for method invocation instructions
        if "invoke" in instr_str:
            # Extract the called method signature
            # Format: invoke-xxx {registers}, Lclass;->method(params)returntype
            try:
                if "->" in instr_str:
                    parts = instr_str.split("->")
                    if len(parts) >= 2:
                        # Find the class part
                        class_part = parts[0].split()[-1]
                        # Get the method part
                        method_part = parts[1].split()[0] if parts[1] else ""

                        if class_part and method_part:
                            called_sig = class_part + "->" + method_part
                            if called_sig not in callees:
                                callees.append(called_sig)
            except Exception:
                pass

    return callees


@jsonrpc
def get_permissions(filepath):
    """
    Get all permissions declared in AndroidManifest.xml.

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A dict containing:
        - permissions: List of requested permissions
        - custom_permissions: List of custom defined permissions
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    from xml.etree import ElementTree as ET

    manifest_text = get_manifest(filepath)
    manifest_text = preprocess_manifest_py2(manifest_text)

    if not manifest_text:
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)

    try:
        root = ET.fromstring(manifest_text.encode('utf-8'))
    except Exception as e:
        print("[MCP] Error parsing manifest:", e)
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)

    ANDROID_NS = 'http://schemas.android.com/apk/res/android'

    # Get requested permissions
    permissions = []
    for uses_permission in root.findall('uses-permission'):
        perm_name = uses_permission.attrib.get('{' + ANDROID_NS + '}name', '')
        if perm_name:
            permissions.append(perm_name)

    # Get custom defined permissions
    custom_permissions = []
    for permission in root.findall('permission'):
        perm_name = permission.attrib.get('{' + ANDROID_NS + '}name', '')
        prot_level = permission.attrib.get('{' + ANDROID_NS + '}protectionLevel', 'normal')
        if perm_name:
            custom_permissions.append({
                "name": perm_name,
                "protectionLevel": prot_level
            })

    return {
        "permissions": permissions,
        "custom_permissions": custom_permissions
    }


@jsonrpc
def get_broadcast_receivers(filepath):
    """
    Get all BroadcastReceiver components from AndroidManifest.xml.

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A list of dicts containing receiver information
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    from xml.etree import ElementTree as ET

    manifest_text = get_manifest(filepath)
    manifest_text = preprocess_manifest_py2(manifest_text)

    if not manifest_text:
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)

    try:
        root = ET.fromstring(manifest_text.encode('utf-8'))
    except Exception as e:
        print("[MCP] Error parsing manifest:", e)
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)

    ANDROID_NS = 'http://schemas.android.com/apk/res/android'
    package_name = root.attrib.get('package', '').strip()

    app_node = root.find('application')
    if app_node is None:
        return []

    receivers = []
    for receiver in app_node.findall('receiver'):
        name = receiver.attrib.get('{' + ANDROID_NS + '}name', '')
        exported = receiver.attrib.get('{' + ANDROID_NS + '}exported', '')
        enabled = receiver.attrib.get('{' + ANDROID_NS + '}enabled', 'true')

        # Get intent filters
        intent_filters = []
        for intent_filter in receiver.findall('intent-filter'):
            actions = []
            for action in intent_filter.findall('action'):
                action_name = action.attrib.get('{' + ANDROID_NS + '}name', '')
                if action_name:
                    actions.append(action_name)
            if actions:
                intent_filters.append(actions)

        if name:
            # Normalize class name
            if name.startswith('.'):
                full_name = 'L' + (package_name + name).replace('.', '/') + ';'
            elif '.' not in name:
                full_name = 'L' + package_name.replace('.', '/') + '/' + name + ';'
            else:
                full_name = 'L' + name.replace('.', '/') + ';'

            receivers.append({
                "class_signature": full_name,
                "exported": exported if exported else ("true" if intent_filters else "false"),
                "enabled": enabled,
                "intent_filters": intent_filters
            })

    return receivers


@jsonrpc
def get_content_providers(filepath):
    """
    Get all ContentProvider components from AndroidManifest.xml.

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A list of dicts containing provider information
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    from xml.etree import ElementTree as ET

    manifest_text = get_manifest(filepath)
    manifest_text = preprocess_manifest_py2(manifest_text)

    if not manifest_text:
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)

    try:
        root = ET.fromstring(manifest_text.encode('utf-8'))
    except Exception as e:
        print("[MCP] Error parsing manifest:", e)
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)

    ANDROID_NS = 'http://schemas.android.com/apk/res/android'
    package_name = root.attrib.get('package', '').strip()

    app_node = root.find('application')
    if app_node is None:
        return []

    providers = []
    for provider in app_node.findall('provider'):
        name = provider.attrib.get('{' + ANDROID_NS + '}name', '')
        authorities = provider.attrib.get('{' + ANDROID_NS + '}authorities', '')
        exported = provider.attrib.get('{' + ANDROID_NS + '}exported', '')
        enabled = provider.attrib.get('{' + ANDROID_NS + '}enabled', 'true')
        read_perm = provider.attrib.get('{' + ANDROID_NS + '}readPermission', '')
        write_perm = provider.attrib.get('{' + ANDROID_NS + '}writePermission', '')

        if name:
            # Normalize class name
            if name.startswith('.'):
                full_name = 'L' + (package_name + name).replace('.', '/') + ';'
            elif '.' not in name:
                full_name = 'L' + package_name.replace('.', '/') + '/' + name + ';'
            else:
                full_name = 'L' + name.replace('.', '/') + ';'

            providers.append({
                "class_signature": full_name,
                "authorities": authorities,
                "exported": exported,
                "enabled": enabled,
                "readPermission": read_perm,
                "writePermission": write_perm
            })

    return providers


@jsonrpc
def find_subclasses(filepath, parent_class_signature):
    """
    Find all subclasses of the given class.

    Args:
        filepath: The absolute path to the APK file
        parent_class_signature: The parent class signature

    Returns:
        A list of class signatures that extend the parent class
    """
    if not filepath or not parent_class_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    codeUnit = apk.getDex()

    all_classes = codeUnit.getClasses()
    subclasses = []

    for clazz in all_classes:
        superclass_sig = clazz.getSupertypeSignature(True)
        if superclass_sig == parent_class_signature:
            subclasses.append(clazz.getSignature(True))

    return subclasses


@jsonrpc
def get_package_tree(filepath):
    """
    Get the package structure tree of the APK.

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A dict representing the package tree with class counts
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    codeUnit = apk.getDex()

    all_classes = codeUnit.getClasses()
    package_tree = {}

    for clazz in all_classes:
        class_sig = clazz.getSignature(True)
        # Extract package from signature (e.g., Lcom/example/app/MainActivity; -> com.example.app)
        if class_sig.startswith('L') and ';' in class_sig:
            path = class_sig[1:class_sig.rfind(';')]
            parts = path.split('/')

            # Build tree structure
            current = package_tree
            for part in parts[:-1]:  # Exclude class name
                if part not in current:
                    current[part] = {"_classes": [], "_subpackages": {}}
                current = current[part]["_subpackages"]

            # Add class to final package
            if len(parts) > 0:
                pkg = parts[-2] if len(parts) > 1 else parts[0]
                if pkg not in current:
                    current[pkg] = {"_classes": [], "_subpackages": {}}
                current[pkg]["_classes"].append(parts[-1])

    return package_tree


@jsonrpc
def identify_third_party_libraries(filepath):
    """
    Identify potential third-party libraries based on common package patterns.

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A dict with library names and their package prefixes
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    codeUnit = apk.getDex()

    # Common third-party library patterns
    library_patterns = {
        "okhttp": "Lokhttp3/",
        "retrofit": "Lretrofit2/",
        "gson": "Lcom/google/gson/",
        "glide": "Lcom/bumptech/glide/",
        "picasso": "Lcom/squareup/picasso/",
        "fresco": "Lcom/facebook/fresco/",
        "rxjava": "Lio/reactivex/",
        "rxandroid": "Lio/reactivex/android/",
        "butterknife": "Lbutterknife/",
        "dagger": "Ldagger/",
        "eventbus": "Lorg/greenrobot/eventbus/",
        "fastjson": "Lcom/alibaba/fastjson/",
        "android_support": "Landroid/support/",
        "androidx": "Landroidx/",
        "kotlin": "Lkotlin/",
        "okio": "Lokio/",
        "protobuf": "Lcom/google/protobuf/"
    }

    all_classes = codeUnit.getClasses()
    found_libraries = {}

    for lib_name, pattern in library_patterns.items():
        count = 0
        for clazz in all_classes:
            class_sig = clazz.getSignature(True)
            if class_sig.startswith(pattern):
                count += 1

        if count > 0:
            found_libraries[lib_name] = {
                "package_prefix": pattern,
                "class_count": count
            }

    return found_libraries


@jsonrpc
def get_field_read_write_refs(filepath, field_signature):
    """
    Get field references separated by read and write operations.

    Args:
        filepath: The absolute path to the APK file
        field_signature: The field signature

    Returns:
        A dict with 'reads' and 'writes' lists
    """
    if not filepath or not field_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    codeUnit = apk.getDex()

    field = codeUnit.getField(field_signature)
    if field is None:
        raise_field_not_found(field_signature)

    all_methods = codeUnit.getMethods()
    reads = []
    writes = []

    for method in all_methods:
        instructions = get_method_instructions(method)
        if instructions is None:
            continue

        for instruction in instructions:
            instr_str = instruction.format(None)

            if field_signature in instr_str:
                # Determine if it's a read or write based on instruction
                if "iget" in instr_str or "sget" in instr_str:
                    # Read operation
                    reads.append({
                        "class_signature": method.getClassType().getSignature(True),
                        "method_signature": method.getSignature(True)
                    })
                elif "iput" in instr_str or "sput" in instr_str:
                    # Write operation
                    writes.append({
                        "class_signature": method.getClassType().getSignature(True),
                        "method_signature": method.getSignature(True)
                    })

    return {
        "reads": reads,
        "writes": writes
    }


@jsonrpc
def rename_method_name(
    filepath, class_signature, method_signature, new_method_name
):
    if not filepath or not class_signature:
        return False

    apk = getOrLoadApk(filepath)
    if apk is None:
        return False

    codeUnit = apk.getDex()
    clazz = codeUnit.getClass(class_signature)
    if clazz is None:
        return False
    for method in clazz.getMethods():
        signature = method.getSignature()
        print("method signature:", signature, "looking for:", method_signature)
        if signature == method_signature:
            print("rename method:", method.getName(), "to", new_method_name)
            method.setName(new_method_name)
            break
    return True


@jsonrpc
def rename_class_field(
    filepath, class_signature, field_signature, new_field_name
):
    if not filepath or not class_signature:
        return False

    apk = getOrLoadApk(filepath)
    if apk is None:
        return False

    codeUnit = apk.getDex()
    clazz = codeUnit.getClass(class_signature)
    if clazz is None:
        return False

    dex_field = clazz.getFields()
    for field in dex_field:
        signature = field.getSignature()
        print("method signature:", signature, "looking for:", field_signature)
        if signature == field_signature:
            print("rename field:", field.getName(), "to", new_field_name)
            field.setName(new_field_name)
            break
    return True


def replace_last_once(s, old, new):
    parts = s.rsplit(old, 1)
    return new.join(parts) if len(parts) > 1 else s


@jsonrpc
def check_java_identifier(filepath, identifier):
    """
    Check an identifier in the APK file and recognize if this is a class, method or field.
    the passed in identifier needs to be a fully-qualified name (like `com.abc.def.Foo`) or a signature;
    the passed in filepath needs to be a fully-qualified absolute path;
    the return value will be a list to tell you the possible type of the passed identifier.
    """
    if not filepath or not identifier:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)
    
    apk = getOrLoadApk(filepath)

    codeUnit = apk.getDex()
    
    result = []

    class_list = codeUnit.getClasses()

    if identifier.startswith("L") and identifier.endswith(";"):
        fake_class_signature = identifier
    else:
        fake_class_signature = "L" + identifier.replace(".", "/") + ";"
    
    for clazz in class_list:
        if clazz.getSignature(True) == fake_class_signature:
            result.append({
                "type": "class",
                "signature": clazz.getSignature(True),
                "parent": clazz.getPackage().getSignature(True)
            })
            # If an identifier is a class, it will never be a method or field.
            return result

    method_list = codeUnit.getMethods()

    if identifier.startswith("L") and ";->" in identifier:
        fake_method_signature = identifier
    else:
        fake_method_signature = replace_last_once("L" + identifier.replace(".", "/"), "/", ";->")

    for method in method_list:
        if method.getSignature(True).startswith(fake_method_signature):
            result.append({
                "type": "method",
                "signature": method.getSignature(True),
                "parent": method.getClassType().getSignature(True)
            })

    field_list = codeUnit.getFields()

    if identifier.startswith("L") and ";->" in identifier:
        fake_field_signature = identifier
    else:
        fake_field_signature = replace_last_once("L" + identifier.replace(".", "/"), "/", ";->")
    
    for field in field_list:
        if field.getSignature(True).startswith(fake_field_signature):
            result.append({
                "type": "field",
                "signature": field.getSignature(True),
                "parent": field.getClassType().getSignature(True)
            })
            break
    
    if len(result) == 0:
        if identifier.startswith("dalvik") or identifier.startswith("Landroid"):
            result.append({
                "type": "Android base type",
                "signature": "N/A",
                "parent": "N/A"
            })
        elif identifier.startswith("Ljava"):
            result.append({
                "type": "Java base type",
                "signature": "N/A",
                "parent": "N/A"
            })
        else:
            result.append({
                "type": "Not found",
                "signature": "N/A",
                "parent": "N/A"
            })
    return result


def raise_class_not_found(class_signature):
    if class_signature.startswith("Ldalvik") or class_signature.startswith("Ljava") or class_signature.startswith("Landroid"):
        raise JSONRPCError(-1, ErrorMessages.CLASS_NOT_FOUND_WITHOUT_CHECK)
    else:
        raise JSONRPCError(-1, ErrorMessages.CLASS_NOT_FOUND)


def raise_method_not_found(method_signature):
    if method_signature.startswith("Ldalvik") or method_signature.startswith("Ljava") or method_signature.startswith("Landroid"):
        raise JSONRPCError(-1, ErrorMessages.METHOD_NOT_FOUND_WITHOUT_CHECK)
    else:
        raise JSONRPCError(-1, ErrorMessages.METHOD_NOT_FOUND)


def raise_field_not_found(field_signature):
    if field_signature.startswith("Ldalvik") or field_signature.startswith("Ljava") or field_signature.startswith("Landroid"):
        raise JSONRPCError(-1, ErrorMessages.FIELD_NOT_FOUND_WITHOUT_CHECK)
    else:
        raise JSONRPCError(-1, ErrorMessages.FIELD_NOT_FOUND)


class ErrorMessages:
    SUCCESS = "[Success]"
    MISSING_PARAM = "[Error] Missing parameter."
    LOAD_APK_FAILED = "[Error] Load apk failed."
    LOAD_APK_NOT_FOUND = "[Error] Apk file not found."
    GET_MANIFEST_FAILED = "[Error] Get AndroidManifest text failed."
    INDEX_OUT_OF_BOUNDS = "[Error] Index out of bounds."
    DECOMPILE_FAILED = "[Error] Failed to decompile code."
    METHOD_NOT_FOUND = "[Error] Method not found in current apk, use check_java_identifier tool check your input first."
    METHOD_NOT_FOUND_WITHOUT_CHECK = "[Error] Method not found in current apk."
    CLASS_NOT_FOUND = "[Error] Class not found in current apk, use check_java_identifier tool check your input first."
    CLASS_NOT_FOUND_WITHOUT_CHECK = "[Error] Class not found in current apk."
    FIELD_NOT_FOUND = "[Error] Field not found in current apk, use check_java_identifier tool check your input first."
    FIELD_NOT_FOUND_WITHOUT_CHECK = "[Error] Field not found in current apk."


CTX = None
class MCP(IScript):
    def __init__(self):
        self.server = Server()
        print("[MCP] Plugin loaded")

    def run(self, ctx):
        global CTX  # Fixed: use global keyword to modify global variable
        CTX = ctx
        self.server.start()
        print("[MCP] Plugin running")

        is_daemon = int(os.getenv("JEB_MCP_DAEMON", "0"))
        if is_daemon == 1:
            try:
                while True:
                    time.sleep(10)
            except KeyboardInterrupt:
                print("Exiting...")

    def term(self):
        self.server.stop()

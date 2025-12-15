# NOTE: This file has been automatically generated, do not modify!
# Architecture based on https://github.com/mrexodia/ida-pro-mcp (MIT License)
from typing import Annotated, TypeVar

T = TypeVar("T")


@mcp.tool()
def ping() -> str:
    """Do a simple ping to check server is alive and running"""
    return make_jsonrpc_request("ping")

@mcp.tool()
def get_manifest(filepath: Annotated[str, "full apk file path."]) -> str:
    """Get the manifest of the given APK file in path, the passed in filepath needs to be a fully-qualified absolute path"""
    return make_jsonrpc_request("get_manifest", filepath)

@mcp.tool()
def get_all_exported_activities(
    filepath: Annotated[str, "full apk file path."],
) -> list[str]:
    """
    Get all exported activity names from the APK manifest.

    This includes activities with:
    - android:exported="true"
    - or no exported attribute but with at least one <intent-filter>
    
    The passed in filepath needs to be a fully-qualified absolute path.
    """
    return make_jsonrpc_request("get_all_exported_activities", filepath)


@mcp.tool()
def get_exported_services(
    filepath: Annotated[str, "full apk file path."]) -> list[str]:
    """
    Get all exported service names from the APK manifest.

    This includes services with:
    - android:exported="true"
    - or no exported attribute but with at least one <intent-filter>
    
    The passed in filepath needs to be a fully-qualified absolute path.
    """
    return make_jsonrpc_request("get_exported_services", filepath)


@mcp.tool()
def get_method_decompiled_code(
    filepath: Annotated[str, "full apk file path."],
    method_signature: Annotated[
        str,
        "the method_signature needs to be a fully-qualified signature e.g. Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V",
    ],
) -> str:
    """Get the decompiled code of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    Dex units use Java-style internal addresses to identify items:
        
    - package: Lcom/abc/
    - type: Lcom/abc/Foo;
    - method: Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    - field: Lcom/abc/Foo;->flag1:Z

    @param filepath: the path to the APK file
    @param method_signature: the fully-qualified method signature to decompile, e.g. Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    the passed in filepath needs to be a fully-qualified absolute path
    """
    return make_jsonrpc_request(
        "get_method_decompiled_code", filepath, method_signature
    )


@mcp.tool()
def get_method_smali_code(
    filepath: Annotated[str, "full apk file path."], method_signature: Annotated[
        str,
        "the method_signature needs to be a fully-qualified signature e.g. Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V",
    ]
) -> str:
    """Get the smali code of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    Dex units use Java-style internal addresses to identify items:
        
    - package: Lcom/abc/
    - type: Lcom/abc/Foo;
    - method: Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    - field: Lcom/abc/Foo;->flag1:Z

    @param filepath: the path to the APK file
    @param method_signature: the fully-qualified method signature to decompile, e.g. Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    the passed in filepath needs to be a fully-qualified absolute path
    """
    return make_jsonrpc_request(
        "get_method_smali_code", filepath, method_signature
    )

@mcp.tool()
def get_class_decompiled_code(
    filepath: Annotated[str, "full apk file path."],
    class_signature: Annotated[
        str, "fully-qualified signature of the class, e.g. Lcom/abc/Foo;"
    ],
) -> str:
    """Get the decompiled code of the given class in the APK file, the passed in class_signature needs to be a fully-qualified signature
    Dex units use Java-style internal addresses to identify items:

    - package: Lcom/abc/
    - type: Lcom/abc/Foo;
    - method: Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    - field: Lcom/abc/Foo;->flag1:Z

    @param: filepath: The path to the APK file
    @param: class_signature: The fully-qualified signature of the class to decompile, e.g. Lcom/abc/Foo;
    the passed in filepath needs to be a fully-qualified absolute path
    """
    return make_jsonrpc_request(
        "get_class_decompiled_code", filepath, class_signature
    )


@mcp.tool()
def get_method_callers(
    filepath: Annotated[str, "full apk file path."],
    method_signature: Annotated[
        str,
        "the method_signature needs to be a fully-qualified signature e.g. Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V",
    ],
) -> list[dict]:
    """
    Get the callers of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    the passed in filepath needs to be a fully-qualified absolute path
    """
    return make_jsonrpc_request(
        "get_method_callers", filepath, method_signature
    )


@mcp.tool()
def get_field_callers(
    filepath: Annotated[str, "full apk file path."],
    field_signature: Annotated[
        str,
        "the field_signature needs to be a fully-qualified signature e.g. Lcom/abc/Foo;->a",
    ],) -> list[dict]:
    """
    Get the callers of the given field in the APK file, the passed in field_signature needs to be a fully-qualified signature
    the passed in filepath needs to be a fully-qualified absolute path
    """
    return make_jsonrpc_request(
        "get_field_callers", filepath, field_signature
    )


@mcp.tool()
def get_method_overrides(
    filepath: Annotated[str, "full apk file path."],
    method_signature: Annotated[
        str,
        "the method_signature needs to be a fully-qualified signature e.g. Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V",
    ],
) -> list[str]:
    """
    Get the overrides of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    the passed in filepath needs to be a fully-qualified absolute path
    """
    return make_jsonrpc_request(
        "get_method_overrides", filepath, method_signature
    )


@mcp.tool()
def get_superclass(
    filepath: Annotated[str, "full apk file path."],
    class_signature: Annotated[
        str, "fully-qualified signature of the class, e.g. Lcom/abc/Foo;"
    ],
) -> str:
    """
    Get the superclass of the given class in the APK file, the passed in class_signature needs to be a fully-qualified signature
    the passed in filepath needs to be a fully-qualified absolute path
    """
    return make_jsonrpc_request("get_superclass", filepath, class_signature)


@mcp.tool()
def get_interfaces(
    filepath: Annotated[str, "full apk file path."],
    class_signature: Annotated[
        str, "fully-qualified signature of the class, e.g. Lcom/abc/Foo;"
    ],
) -> list[str]:
    """
    Get the interfaces of the given class in the APK file, the passed in class_signature needs to be a fully-qualified signature
    the passed in filepath needs to be a fully-qualified absolute path
    """
    return make_jsonrpc_request("get_interfaces", filepath, class_signature)


@mcp.tool()
def get_class_methods(
    filepath: Annotated[str, "full apk file path."],
    class_signature: Annotated[
        str, "fully-qualified signature of the class, e.g. Lcom/abc/Foo;"
    ],
) -> list[str]:
    """
    Get the methods of the given class in the APK file, the passed in class_signature needs to be a fully-qualified signature
    the passed in filepath needs to be a fully-qualified absolute path
    """
    return make_jsonrpc_request("get_class_methods", filepath, class_signature)


@mcp.tool()
def get_class_fields(
    filepath: Annotated[str, "full apk file path."],
    class_signature: Annotated[
        str, "fully-qualified signature of the class, e.g. Lcom/abc/Foo;"
    ],
) -> list[str]:
    """
    Get the fields of the given class in the APK file, the passed in class_signature needs to be a fully-qualified signature
    the passed in filepath needs to be a fully-qualified absolute path
    """
    return make_jsonrpc_request("get_class_fields", filepath, class_signature)


@mcp.tool()
def rename_class_name(
    filepath: Annotated[str, "full apk file path"],
    class_signature: Annotated[
        str, "fully-qualified signature of the class, e.g. Lcom/abc/Foo;"
    ],
    new_class_name: Annotated[
        str,
        "the new name for java class name without package and type, e.g. 'MyNewClass'",
    ],
):
    """rename the given class in the APK file

    Args:
        filepath (str): full apk file path.
        class_signature (str): fully-qualified signature of the class, e.g. Lcom/abc/Foo;
        new_class_name (str): the new name for java class name without package and type, e.g. "MyNewClass"

    Returns:
        None
    """
    return make_jsonrpc_request(
        "rename_class_name", filepath, class_signature, new_class_name
    )


@mcp.tool()
def rename_method_name(
    filepath: Annotated[str, "full apk file path"],
    class_signature: Annotated[
        str, "fully-qualified signature of the class, e.g. Lcom/abc/Foo;"
    ],
    method_signature: Annotated[
        str,
        "the method_signature needs to be a fully-qualified signature e.g. Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V",
    ],
    new_method_name: Annotated[
        str,
        "the new name for java method name without parameters, e.g. 'myNewMethod'",
    ],
):
    """rename the given class method in the APK file

    Args:
        filepath (str): full apk file path.
        class_signature (str): fully-qualified signature of the class, e.g. Lcom/abc/Foo;
        method_signature (str): the method_signature needs to be a fully-qualified signature e.g. Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
        new_method_name (str): the new name for java method name without parameters, e.g. "myNewMethod"

    Returns:
        None
    """
    return make_jsonrpc_request(
        "rename_method_name",
        filepath,
        class_signature,
        method_signature,
        new_method_name,
    )


@mcp.tool()
def rename_class_field(
    filepath: Annotated[str, "full apk file path"],
    class_signature: Annotated[
        str, "fully-qualified signature of the class, e.g. Lcom/abc/Foo;"
    ],
    field_signature: Annotated[
        str,
        "the field_signature needs to be a fully-qualified signature e.g. Lcom/abc/Foo;->flag1:Z",
    ],
    new_field_name: Annotated[
        str, "the new name for java field name without type, e.g. 'myNewField'"
    ],
):
    """rename the given class field in the APK file

    Args:
        filepath (str): _description_
        class_signature (str): class_signature needs to be a fully-qualified signature e.g. Lcom/abc/Foo;
        field_signature (str): the field_signature needs to be a fully-qualified signature e.g. Lcom/abc/Foo;->flag1:Z
        new_field_name (str): the new name for java field name without type, e.g. "myNewField"

    Returns:
        None
    """
    return make_jsonrpc_request(
        "rename_class_field",
        filepath,
        class_signature,
        field_signature,
        new_field_name,
    )

@mcp.tool()
def check_java_identifier(
    filepath: Annotated[str, "full apk file path"],
    identifier: Annotated[
        str,
        "the passed in identifier needs to be a fully-qualified name (like `com.abc.def.Foo`) or a signature;",
    ],) -> list[dict]:
    """
    Check an identifier in the APK file and recognize if this is a class, type, method or field.
    the passed in identifier needs to be a fully-qualified name (like `com.abc.def.Foo`) or a signature;
    the passed in filepath needs to be a fully-qualified absolute path;
    the return value will be a list to tell you the possible type of the passed identifier.
    """
    return make_jsonrpc_request("check_java_identifier", filepath, identifier)


@mcp.tool()
def get_all_classes(
    filepath: Annotated[str, "full apk file path"],
    offset: Annotated[int, "starting index (0-based)"] = 0,
    limit: Annotated[int, "maximum number of classes to return (0 means return all remaining)"] = 100,
) -> dict:
    """
    Get all class signatures in the APK file with pagination support.

    Args:
        filepath: The absolute path to the APK file
        offset: The starting index (0-based), default 0
        limit: The maximum number of classes to return (0 means return all remaining), default 100

    Returns:
        A dict containing:
        - classes: List of class signatures
        - total: Total number of classes
        - offset: The offset used
        - limit: The limit used
        - has_more: Whether there are more classes available
    """
    return make_jsonrpc_request("get_all_classes", filepath, offset, limit)


@mcp.tool()
def get_all_strings(
    filepath: Annotated[str, "full apk file path"],
    offset: Annotated[int, "starting index (0-based)"] = 0,
    limit: Annotated[int, "maximum number of strings to return (0 means return all remaining)"] = 100,
) -> dict:
    """
    Get all strings in the APK file with pagination support.

    Args:
        filepath: The absolute path to the APK file
        offset: The starting index (0-based), default 0
        limit: The maximum number of strings to return (0 means return all remaining), default 100

    Returns:
        A dict containing:
        - strings: List of strings
        - total: Total number of strings
        - offset: The offset used
        - limit: The limit used
        - has_more: Whether there are more strings available
    """
    return make_jsonrpc_request("get_all_strings", filepath, offset, limit)


@mcp.tool()
def search_classes(
    filepath: Annotated[str, "full apk file path"],
    keyword: Annotated[str, "the keyword to search for (case-insensitive)"],
) -> list[str]:
    """
    Search for classes whose name contains the specified keyword.

    Args:
        filepath: The absolute path to the APK file
        keyword: The keyword to search for (case-insensitive)

    Returns:
        A list of matching class signatures
    """
    return make_jsonrpc_request("search_classes", filepath, keyword)


@mcp.tool()
def search_methods(
    filepath: Annotated[str, "full apk file path"],
    keyword: Annotated[str, "the keyword to search for (case-insensitive)"],
) -> list[str]:
    """
    Search for methods whose signature contains the specified keyword.

    Args:
        filepath: The absolute path to the APK file
        keyword: The keyword to search for (case-insensitive)

    Returns:
        A list of matching method signatures
    """
    return make_jsonrpc_request("search_methods", filepath, keyword)


@mcp.tool()
def search_strings(
    filepath: Annotated[str, "full apk file path"],
    keyword: Annotated[str, "the keyword to search for (case-sensitive)"],
) -> list[str]:
    """
    Search for strings that contain the specified keyword.

    Args:
        filepath: The absolute path to the APK file
        keyword: The keyword to search for (case-sensitive)

    Returns:
        A list of matching strings
    """
    return make_jsonrpc_request("search_strings", filepath, keyword)


@mcp.tool()
def find_string_usages(
    filepath: Annotated[str, "full apk file path"],
    target_string: Annotated[str, "the string to search for"],
) -> list[dict]:
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
    return make_jsonrpc_request("find_string_usages", filepath, target_string)


@mcp.tool()
def get_main_activity(
    filepath: Annotated[str, "full apk file path"],
) -> str:
    """
    Get the main activity class signature from AndroidManifest.xml.

    This finds the activity with MAIN action and LAUNCHER category.

    Args:
        filepath: The absolute path to the APK file

    Returns:
        The main activity class signature, or None if not found
    """
    return make_jsonrpc_request("get_main_activity", filepath)


@mcp.tool()
def get_application_class(
    filepath: Annotated[str, "full apk file path"],
) -> str:
    """
    Get the Application class signature from AndroidManifest.xml.

    Args:
        filepath: The absolute path to the APK file

    Returns:
        The Application class signature, or None if using default Application class
    """
    return make_jsonrpc_request("get_application_class", filepath)


@mcp.tool()
def get_classes_batch(
    filepath: Annotated[str, "full apk file path"],
    class_signatures: Annotated[list[str], "list of class signatures to decompile"],
) -> dict:
    """
    Batch get decompiled code for multiple classes to reduce RPC calls.

    Args:
        filepath: The absolute path to the APK file
        class_signatures: List of class signatures to decompile

    Returns:
        A dict mapping class_signature to decompiled code (or error message)
    """
    return make_jsonrpc_request("get_classes_batch", filepath, class_signatures)


@mcp.tool()
def find_native_methods(
    filepath: Annotated[str, "full apk file path"],
) -> list[dict]:
    """
    Find all native method declarations (JNI methods) in the APK.

    This is crucial for reverse engineering as native code is often used
    for security-sensitive operations and obfuscation.

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A list of dicts containing:
        - class_signature: The class containing the native method
        - method_signature: The native method signature
        - method_name: The method name
    """
    return make_jsonrpc_request("find_native_methods", filepath)


@mcp.tool()
def find_reflection_calls(
    filepath: Annotated[str, "full apk file path"],
) -> list[dict]:
    """
    Find all reflection API calls (Class.forName, getDeclaredMethod, invoke, etc.).

    Reflection is commonly used for:
    - Dynamic code loading
    - Obfuscation bypass
    - Plugin systems
    - Framework internals

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A list of dicts containing:
        - class_signature: The class making the reflection call
        - method_signature: The method making the reflection call
        - reflection_type: Type of reflection API (forName, getDeclaredMethod, etc.)
        - instruction: The actual instruction
    """
    return make_jsonrpc_request("find_reflection_calls", filepath)


@mcp.tool()
def find_crypto_usage(
    filepath: Annotated[str, "full apk file path"],
) -> list[dict]:
    """
    Find all cryptography API usage (Cipher, MessageDigest, SecretKey, etc.).

    Identifies encryption, hashing, and key management operations which are
    critical for security analysis.

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A list of dicts containing:
        - class_signature: The class using crypto APIs
        - method_signature: The method using crypto APIs
        - crypto_apis: List of crypto APIs being used
    """
    return make_jsonrpc_request("find_crypto_usage", filepath)


@mcp.tool()
def find_network_usage(
    filepath: Annotated[str, "full apk file path"],
) -> list[dict]:
    """
    Find all network API usage (HttpURLConnection, OkHttp, Socket, etc.).

    Identifies network communication points which are essential for:
    - API endpoint discovery
    - Protocol analysis
    - Data exfiltration detection

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A list of dicts containing:
        - class_signature: The class using network APIs
        - method_signature: The method using network APIs
        - network_apis: List of network APIs being used
    """
    return make_jsonrpc_request("find_network_usage", filepath)


@mcp.tool()
def find_file_operations(
    filepath: Annotated[str, "full apk file path"],
) -> list[dict]:
    """
    Find all file operation API usage (File, FileInputStream, SharedPreferences, etc.).

    Identifies data storage and retrieval operations including:
    - File I/O
    - SharedPreferences access
    - SQLite database operations

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A list of dicts containing:
        - class_signature: The class performing file operations
        - method_signature: The method performing file operations
        - file_apis: List of file APIs being used
    """
    return make_jsonrpc_request("find_file_operations", filepath)


@mcp.tool()
def find_dynamic_loading(
    filepath: Annotated[str, "full apk file path"],
) -> list[dict]:
    """
    Find all dynamic code loading (DexClassLoader, PathClassLoader, etc.).

    Dynamic loading is often used for:
    - Plugin systems
    - Hot fixes
    - Malicious payload loading
    - Anti-analysis techniques

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A list of dicts containing:
        - class_signature: The class performing dynamic loading
        - method_signature: The method performing dynamic loading
        - loader_type: Type of class loader being used
        - instruction: The actual instruction
    """
    return make_jsonrpc_request("find_dynamic_loading", filepath)


@mcp.tool()
def get_method_callees(
    filepath: Annotated[str, "full apk file path"],
    method_signature: Annotated[str, "the method signature to analyze"],
) -> list[str]:
    """
    Get all methods called by the given method (callees).

    This complements get_method_callers to provide full call graph analysis.

    Args:
        filepath: The absolute path to the APK file
        method_signature: The method signature to analyze

    Returns:
        A list of method signatures that are called by this method
    """
    return make_jsonrpc_request("get_method_callees", filepath, method_signature)


@mcp.tool()
def get_permissions(
    filepath: Annotated[str, "full apk file path"],
) -> dict:
    """
    Get all permissions declared in AndroidManifest.xml.

    Essential for understanding the app's capability boundaries and
    potential security risks.

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A dict containing:
        - permissions: List of requested permissions
        - custom_permissions: List of custom defined permissions
    """
    return make_jsonrpc_request("get_permissions", filepath)


@mcp.tool()
def get_broadcast_receivers(
    filepath: Annotated[str, "full apk file path"],
) -> list[dict]:
    """
    Get all BroadcastReceiver components from AndroidManifest.xml.

    Receivers are entry points that respond to system or app broadcasts.

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A list of dicts containing:
        - class_signature: The receiver class
        - exported: Whether the receiver is exported
        - enabled: Whether the receiver is enabled
        - intent_filters: List of intent filter actions
    """
    return make_jsonrpc_request("get_broadcast_receivers", filepath)


@mcp.tool()
def get_content_providers(
    filepath: Annotated[str, "full apk file path"],
) -> list[dict]:
    """
    Get all ContentProvider components from AndroidManifest.xml.

    Providers expose app data and are potential attack surfaces.

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A list of dicts containing:
        - class_signature: The provider class
        - authorities: The provider authorities
        - exported: Whether the provider is exported
        - readPermission: Required permission for reading
        - writePermission: Required permission for writing
    """
    return make_jsonrpc_request("get_content_providers", filepath)


@mcp.tool()
def find_subclasses(
    filepath: Annotated[str, "full apk file path"],
    parent_class_signature: Annotated[str, "parent class signature"],
) -> list[str]:
    """
    Find all subclasses of the given class.

    Useful for:
    - Finding implementations of abstract classes
    - Discovering plugin architectures
    - Understanding inheritance hierarchies

    Args:
        filepath: The absolute path to the APK file
        parent_class_signature: The parent class signature

    Returns:
        A list of class signatures that extend the parent class
    """
    return make_jsonrpc_request("find_subclasses", filepath, parent_class_signature)


@mcp.tool()
def get_package_tree(
    filepath: Annotated[str, "full apk file path"],
) -> dict:
    """
    Get the package structure tree of the APK.

    Provides a high-level overview of code organization, helpful for:
    - Understanding architecture
    - Identifying code modules
    - Planning analysis strategy

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A dict representing the package tree with class counts
    """
    return make_jsonrpc_request("get_package_tree", filepath)


@mcp.tool()
def identify_third_party_libraries(
    filepath: Annotated[str, "full apk file path"],
) -> dict:
    """
    Identify potential third-party libraries based on common package patterns.

    Helps quickly filter out library code to focus on application logic.

    Detects libraries including:
    - OkHttp, Retrofit (networking)
    - Gson, FastJSON (JSON parsing)
    - Glide, Picasso (image loading)
    - RxJava (reactive programming)
    - And many more...

    Args:
        filepath: The absolute path to the APK file

    Returns:
        A dict with library names, package prefixes, and class counts
    """
    return make_jsonrpc_request("identify_third_party_libraries", filepath)


@mcp.tool()
def get_field_read_write_refs(
    filepath: Annotated[str, "full apk file path"],
    field_signature: Annotated[str, "field signature"],
) -> dict:
    """
    Get field references separated by read and write operations.

    Provides data flow analysis by distinguishing between reads and writes.

    Args:
        filepath: The absolute path to the APK file
        field_signature: The field signature

    Returns:
        A dict with 'reads' and 'writes' lists, each containing:
        - class_signature: The class accessing the field
        - method_signature: The method accessing the field
    """
    return make_jsonrpc_request("get_field_read_write_refs", filepath, field_signature)

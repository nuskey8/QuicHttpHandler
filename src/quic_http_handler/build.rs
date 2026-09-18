fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/client.rs");
    generate_bindings("../QuicHttpHandler.Interop/NativeMethods.g.cs");
    generate_bindings(
        "../QuicHttpHandler.Unity/Packages/QuicHttpHandler.Unity/Interop/NativeMethods.g.cs",
    );
}

fn generate_bindings(path: &str) {
    csbindgen::Builder::default()
        .input_extern_file("src/client.rs")
        .csharp_namespace("Nuskey.Net.Quic.Interop")
        .csharp_class_name("NativeMethods")
        .csharp_class_accessibility("public")
        .csharp_dll_name("quic_http_handler")
        .csharp_dll_name_if("UNITY_IOS && !UNITY_EDITOR", "__Internal")
        .csharp_use_function_pointer(false)
        .csharp_file_header("#if !UNITY_WEBGL")
        .csharp_file_footer("#endif")
        .generate_csharp_file(path)
        .expect("failed to generate C# bindings");
}

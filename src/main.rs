use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const APP_NAME: &str = "SysInspectAgent";
const BIN_NAME: &str = "sysinspect";
const VERSION: &str = "1.0.0";
const DEFAULT_INTERVAL: u64 = 3600;
const DEFAULT_TIMEOUT: u64 = 30;

static SERVICE_MODE: AtomicBool = AtomicBool::new(false);
static LOG_STDERR: AtomicBool = AtomicBool::new(false);

fn print_version() {
    println!("{} {}", APP_NAME, VERSION);
}

fn print_help() {
    println!(
        "PC SysInspector Agent {ver}
Collects hardware and software information from a Windows computer (WMI) and
sends it as JSON via HTTP POST requests. Can run as a CLI application or a Windows service.

USAGE:
    {bin} [OPTIONS] <URL>
    {bin} --url <URL> [OPTIONS]
    {bin} --install --url <URL> [--interval <SEC>] [--name <NAME>]
    {bin} --uninstall | --start | --stop [--name <NAME>]

OPTIONS:
    -u, --url <URL>        Server endpoint (http:// or https://)
    -i, --interval <SEC>   Reporting interval in service mode (default: {interval})
    -t, --timeout <SEC>    HTTP request timeout (default: {timeout})
    -n, --name <NAME>      Service name (default: {app})
        --dry-run          Collect data and print JSON to stdout without sending it

SERVICE MANAGEMENT (administrator privileges required):
        --install          Install the service (automatic startup); requires --url
        --uninstall        Stop and remove the service
        --start            Start the service
        --stop             Stop the service
        --service          Internal flag: run under Service Control Manager (SCM)
                           (not intended for manual use)

MISCELLANEOUS:
    -h, --help             Display this help message
    -V, --version          Display version information

EXAMPLES:
    {bin} http://srv.local:8080/api/inspector
    {bin} --dry-run > inventory.json
    {bin} --install --url http://srv.local:8080/api/inspector --interval 7200
    {bin} --start

SERVICE LOG:
    %ProgramData%\\{app}\\agent.log

EXIT CODES:
    0 - success, 1 - runtime error, 2 - invalid arguments",
        ver = VERSION,
        bin = BIN_NAME,
        app = APP_NAME,
        interval = DEFAULT_INTERVAL,
        timeout = DEFAULT_TIMEOUT
    );
}

#[derive(Clone, Debug)]
struct Config {
    url: Option<String>,
    interval: u64,
    timeout: u64,
    name: String,
    dry_run: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            url: None,
            interval: DEFAULT_INTERVAL,
            timeout: DEFAULT_TIMEOUT,
            name: APP_NAME.to_string(),
            dry_run: false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Action {
    Run,
    Service,
    Install,
    Uninstall,
    Start,
    Stop,
    Help,
    Version,
}

fn take_value(
    i: &mut usize,
    inline: Option<String>,
    args: &[String],
    key: &str,
) -> Result<String, String> {
    if let Some(v) = inline {
        return Ok(v);
    }
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("option '{}' requires a value", key))
}

fn set_action(cur: &mut Action, new: Action) -> Result<(), String> {
    if *cur != Action::Run && *cur != new {
        return Err("multiple commands cannot be specified at the same time".to_string());
    }
    *cur = new;
    Ok(())
}

fn parse_args(args: &[String]) -> Result<(Action, Config), String> {
    let mut cfg = Config::default();
    let mut action = Action::Run;

    if args.is_empty() {
        return Ok((Action::Help, cfg));
    }

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let (key, inline) = match a.split_once('=') {
            Some((k, v)) if k.starts_with("--") => (k, Some(v.to_string())),
            _ => (a, None),
        };
        match key {
            "-h" | "--help" | "/?" => return Ok((Action::Help, cfg)),
            "-V" | "--version" => return Ok((Action::Version, cfg)),
            "-u" | "--url" => cfg.url = Some(take_value(&mut i, inline, args, key)?),
            "-i" | "--interval" => {
                let v = take_value(&mut i, inline, args, key)?;
                cfg.interval = v
                    .parse::<u64>()
                    .ok()
                    .filter(|n| *n >= 10)
                    .ok_or_else(|| format!("invalid interval '{}' (minimum: 10 seconds)", v))?;
            }
            "-t" | "--timeout" => {
                let v = take_value(&mut i, inline, args, key)?;
                cfg.timeout = v
                    .parse::<u64>()
                    .ok()
                    .filter(|n| *n >= 1)
                    .ok_or_else(|| format!("invalid timeout '{}'", v))?;
            }
            "-n" | "--name" => cfg.name = take_value(&mut i, inline, args, key)?,
            "--dry-run" => cfg.dry_run = true,
            "--service" => set_action(&mut action, Action::Service)?,
            "--install" => set_action(&mut action, Action::Install)?,
            "--uninstall" => set_action(&mut action, Action::Uninstall)?,
            "--start" => set_action(&mut action, Action::Start)?,
            "--stop" => set_action(&mut action, Action::Stop)?,
            _ if !a.starts_with('-') => {
                if cfg.url.is_some() {
                    return Err(format!("unexpected argument '{}'", a));
                }
                cfg.url = Some(a.to_string());
            }
            _ => return Err(format!("unknown option '{}'", a)),
        }
        i += 1;
    }

    let needs_url = match action {
        Action::Run => !cfg.dry_run,
        Action::Service | Action::Install => true,
        _ => false,
    };
    if needs_url {
        match &cfg.url {
            None => return Err("server URL not specified".to_string()),
            Some(u) => {
                parse_url(u)?;
            }
        }
    }
    Ok((action, cfg))
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn civil_from_days(mut days: u64) -> (u64, u64, u64) {
    let mut y = 1970;
    loop {
        let yl = if is_leap(y) { 366 } else { 365 };
        if days < yl {
            break;
        }
        days -= yl;
        y += 1;
    }
    let ml = [
        31,
        if is_leap(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0;
    while days >= ml[m] {
        days -= ml[m];
        m += 1;
    }
    (y, m as u64 + 1, days + 1)
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn current_year() -> u64 {
    civil_from_days(unix_secs() / 86400).0
}

fn utc_now() -> String {
    let s = unix_secs();
    let (y, mo, d) = civil_from_days(s / 86400);
    let r = s % 86400;
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
        y,
        mo,
        d,
        r / 3600,
        (r % 3600) / 60,
        r % 60
    )
}

fn log_file_path() -> PathBuf {
    env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir)
        .join(APP_NAME)
        .join("agent.log")
}

fn log(msg: &str) {
    if SERVICE_MODE.load(Ordering::Relaxed) {
        let path = log_file_path();
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
        }

        if fs::metadata(&path)
            .map(|m| m.len() > 1_048_576)
            .unwrap_or(false)
        {
            let old = path.with_extension("old");
            let _ = fs::remove_file(&old);
            let _ = fs::rename(&path, &old);
        }
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(f, "[{}] {}", utc_now(), msg);
        }
    } else if LOG_STDERR.load(Ordering::Relaxed) {
        eprintln!("{}", msg);
    } else {
        println!("{}", msg);
    }
}

#[cfg(windows)]
mod wmi {
    use std::ffi::c_void;
    use std::mem::transmute;
    use std::ptr::{null, null_mut};

    type HRESULT = i32;

    #[repr(C)]
    struct Guid {
        d1: u32,
        d2: u16,
        d3: u16,
        d4: [u8; 8],
    }

    static CLSID_WBEM_LOCATOR: Guid = Guid {
        d1: 0x4590F811,
        d2: 0x1D3A,
        d3: 0x11D0,
        d4: [0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24],
    };

    static IID_IWBEM_LOCATOR: Guid = Guid {
        d1: 0xDC12A687,
        d2: 0x737F,
        d3: 0x11CF,
        d4: [0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24],
    };

    #[repr(C)]
    struct Variant {
        vt: u16,
        r1: u16,
        r2: u16,
        r3: u16,
        data: [usize; 2],
    }

    impl Variant {
        fn empty() -> Self {
            Variant {
                vt: 0,
                r1: 0,
                r2: 0,
                r3: 0,
                data: [0; 2],
            }
        }
    }

    #[link(name = "ole32")]
    unsafe extern "system" {
        fn CoInitializeEx(reserved: *mut c_void, coinit: u32) -> HRESULT;
        fn CoUninitialize();
        fn CoInitializeSecurity(
            sd: *mut c_void,
            c_auth_svc: i32,
            as_auth_svc: *mut c_void,
            reserved1: *mut c_void,
            authn_level: u32,
            imp_level: u32,
            auth_list: *mut c_void,
            capabilities: u32,
            reserved3: *mut c_void,
        ) -> HRESULT;
        fn CoCreateInstance(
            clsid: *const Guid,
            outer: *mut c_void,
            ctx: u32,
            iid: *const Guid,
            out: *mut *mut c_void,
        ) -> HRESULT;
        fn CoSetProxyBlanket(
            proxy: *mut c_void,
            authn_svc: u32,
            authz_svc: u32,
            server_princ: *const u16,
            authn_level: u32,
            imp_level: u32,
            auth_info: *mut c_void,
            caps: u32,
        ) -> HRESULT;
    }

    #[link(name = "oleaut32")]
    unsafe extern "system" {
        fn SysAllocString(s: *const u16) -> *mut u16;
        fn SysFreeString(s: *mut u16);
        fn SysStringLen(s: *const u16) -> u32;
        fn VariantClear(v: *mut Variant) -> HRESULT;
        fn VariantChangeTypeEx(
            dest: *mut Variant,
            src: *const Variant,
            lcid: u32,
            flags: u16,
            vt: u16,
        ) -> HRESULT;
        fn SafeArrayGetLBound(sa: *mut c_void, dim: u32, out: *mut i32) -> HRESULT;
        fn SafeArrayGetUBound(sa: *mut c_void, dim: u32, out: *mut i32) -> HRESULT;
        fn SafeArrayGetElement(sa: *mut c_void, indices: *const i32, out: *mut c_void) -> HRESULT;
    }

    const COINIT_MULTITHREADED: u32 = 0;
    const CLSCTX_INPROC_SERVER: u32 = 1;
    const RPC_E_CHANGED_MODE: u32 = 0x8001_0106;
    const RPC_C_AUTHN_WINNT: u32 = 10;
    const RPC_C_AUTHN_LEVEL_CALL: u32 = 3;
    const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;
    const LCID_INVARIANT: u32 = 0x007F;
    const VARIANT_ALPHABOOL: u16 = 0x2;
    const WBEM_FLAG_FORWARD_ONLY_RETURN_IMMEDIATELY: i32 = 0x20 | 0x10;
    const WBEM_FLAG_NONSYSTEM_ONLY: i32 = 0x40;

    const VT_BSTR: u16 = 8;
    const VT_DISPATCH: u16 = 9;
    const VT_VARIANT: u16 = 12;
    const VT_UNKNOWN: u16 = 13;
    const VT_ARRAY: u16 = 0x2000;
    const VT_BYREF: u16 = 0x4000;

    type FnConnect = unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        *const u16,
        *const u16,
        *const u16,
        i32,
        *const u16,
        *mut c_void,
        *mut *mut c_void,
    ) -> HRESULT;
    type FnExecQuery = unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        *const u16,
        i32,
        *mut c_void,
        *mut *mut c_void,
    ) -> HRESULT;
    type FnEnumNext =
        unsafe extern "system" fn(*mut c_void, i32, u32, *mut *mut c_void, *mut u32) -> HRESULT;
    type FnBeginEnum = unsafe extern "system" fn(*mut c_void, i32) -> HRESULT;
    type FnObjNext = unsafe extern "system" fn(
        *mut c_void,
        i32,
        *mut *mut u16,
        *mut Variant,
        *mut i32,
        *mut i32,
    ) -> HRESULT;
    type FnEndEnum = unsafe extern "system" fn(*mut c_void) -> HRESULT;
    type FnRelease = unsafe extern "system" fn(*mut c_void) -> u32;

    const IDX_RELEASE: usize = 2;
    const IDX_LOCATOR_CONNECT_SERVER: usize = 3;
    const IDX_SERVICES_EXEC_QUERY: usize = 20;
    const IDX_ENUM_NEXT: usize = 4;
    const IDX_OBJ_BEGIN_ENUMERATION: usize = 8;
    const IDX_OBJ_NEXT: usize = 9;
    const IDX_OBJ_END_ENUMERATION: usize = 10;

    fn slot(p: *mut c_void, idx: usize) -> usize {
        unsafe {
            let vtbl = *(p as *const *const usize);
            *vtbl.add(idx)
        }
    }

    fn hr_str(hr: HRESULT) -> String {
        format!("HRESULT 0x{:08X}", hr as u32)
    }

    struct Com(*mut c_void);

    impl Drop for Com {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let f: FnRelease = transmute(slot(self.0, IDX_RELEASE));
                    f(self.0);
                }
            }
        }
    }

    struct Bstr(*mut u16);

    impl Bstr {
        fn new(s: &str) -> Bstr {
            let w: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
            Bstr(unsafe { SysAllocString(w.as_ptr()) })
        }
    }

    impl Drop for Bstr {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { SysFreeString(self.0) };
            }
        }
    }

    fn bstr_to_string(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        unsafe {
            let len = SysStringLen(p) as usize;
            String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
        }
    }

    fn change_to_string(src: &Variant) -> String {
        let mut dst = Variant::empty();
        let hr = unsafe {
            VariantChangeTypeEx(&mut dst, src, LCID_INVARIANT, VARIANT_ALPHABOOL, VT_BSTR)
        };
        if hr < 0 {
            return String::new();
        }
        let s = bstr_to_string(dst.data[0] as *const u16);
        unsafe { VariantClear(&mut dst) };
        s
    }

    fn array_first(v: &Variant) -> String {
        let sa = v.data[0] as *mut c_void;
        if sa.is_null() {
            return String::new();
        }
        let elem_vt = v.vt & 0x0FFF;
        let (mut lb, mut ub) = (0i32, -1i32);
        unsafe {
            if SafeArrayGetLBound(sa, 1, &mut lb) < 0 || SafeArrayGetUBound(sa, 1, &mut ub) < 0 {
                return String::new();
            }
        }
        if ub < lb {
            return String::new();
        }
        match elem_vt {
            VT_BSTR => {
                let mut p: *mut u16 = null_mut();
                let hr = unsafe { SafeArrayGetElement(sa, &lb, &mut p as *mut _ as *mut c_void) };
                if hr < 0 {
                    return String::new();
                }
                let s = bstr_to_string(p);
                unsafe { SysFreeString(p) };
                s
            }
            VT_VARIANT => {
                let mut inner = Variant::empty();
                let hr =
                    unsafe { SafeArrayGetElement(sa, &lb, &mut inner as *mut _ as *mut c_void) };
                if hr < 0 {
                    return String::new();
                }
                let s = variant_to_string(&inner);
                unsafe { VariantClear(&mut inner) };
                s
            }
            VT_UNKNOWN | VT_DISPATCH => String::new(),
            _ => {
                let mut buf = [0u8; 8];
                let hr = unsafe { SafeArrayGetElement(sa, &lb, buf.as_mut_ptr() as *mut c_void) };
                if hr < 0 {
                    return String::new();
                }
                let mut inner = Variant::empty();
                inner.vt = elem_vt;
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        buf.as_ptr(),
                        inner.data.as_mut_ptr() as *mut u8,
                        8,
                    );
                }
                change_to_string(&inner)
            }
        }
    }

    fn variant_to_string(v: &Variant) -> String {
        let vt = v.vt;
        if vt == 0 || vt == 1 {
            return String::new();
        }
        if vt & VT_BYREF != 0 {
            return String::new();
        }
        if vt & VT_ARRAY != 0 {
            return array_first(v);
        }
        match vt {
            VT_BSTR => bstr_to_string(v.data[0] as *const u16),
            VT_UNKNOWN | VT_DISPATCH => String::new(),
            _ => change_to_string(v),
        }
    }

    fn blanket(p: *mut c_void) {
        unsafe {
            CoSetProxyBlanket(
                p,
                RPC_C_AUTHN_WINNT,
                0,
                null(),
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                null_mut(),
                0,
            );
        }
    }

    struct ComGuard(bool);

    impl Drop for ComGuard {
        fn drop(&mut self) {
            if self.0 {
                unsafe { CoUninitialize() };
            }
        }
    }

    pub struct Wmi {
        services: Com,
        _guard: ComGuard,
    }

    impl Wmi {
        pub fn open() -> Result<Wmi, String> {
            let hr = unsafe { CoInitializeEx(null_mut(), COINIT_MULTITHREADED) };
            let guard = ComGuard(hr >= 0);
            if hr < 0 && hr as u32 != RPC_E_CHANGED_MODE {
                return Err(format!("CoInitializeEx: {}", hr_str(hr)));
            }

            unsafe {
                CoInitializeSecurity(
                    null_mut(),
                    -1,
                    null_mut(),
                    null_mut(),
                    0,
                    RPC_C_IMP_LEVEL_IMPERSONATE,
                    null_mut(),
                    0,
                    null_mut(),
                );
            }

            let mut loc: *mut c_void = null_mut();
            let hr = unsafe {
                CoCreateInstance(
                    &CLSID_WBEM_LOCATOR,
                    null_mut(),
                    CLSCTX_INPROC_SERVER,
                    &IID_IWBEM_LOCATOR,
                    &mut loc,
                )
            };
            if hr < 0 {
                return Err(format!("CoCreateInstance(WbemLocator): {}", hr_str(hr)));
            }
            let locator = Com(loc);

            let ns = Bstr::new("ROOT\\CIMV2");
            let mut svc: *mut c_void = null_mut();
            let hr = unsafe {
                let f: FnConnect = transmute(slot(locator.0, IDX_LOCATOR_CONNECT_SERVER));
                f(
                    locator.0,
                    ns.0,
                    null(),
                    null(),
                    null(),
                    0,
                    null(),
                    null_mut(),
                    &mut svc,
                )
            };
            if hr < 0 {
                return Err(format!("ConnectServer: {}", hr_str(hr)));
            }
            let services = Com(svc);
            blanket(services.0);

            Ok(Wmi {
                services,
                _guard: guard,
            })
        }

        pub fn query(&self, wql: &str) -> Result<Vec<Vec<(String, String)>>, String> {
            let lang = Bstr::new("WQL");
            let q = Bstr::new(wql);
            let mut en_ptr: *mut c_void = null_mut();
            let hr = unsafe {
                let f: FnExecQuery = transmute(slot(self.services.0, IDX_SERVICES_EXEC_QUERY));
                f(
                    self.services.0,
                    lang.0,
                    q.0,
                    WBEM_FLAG_FORWARD_ONLY_RETURN_IMMEDIATELY,
                    null_mut(),
                    &mut en_ptr,
                )
            };
            if hr < 0 {
                return Err(hr_str(hr));
            }
            let en = Com(en_ptr);
            blanket(en.0);

            let mut result = Vec::new();
            loop {
                let mut obj_ptr: *mut c_void = null_mut();
                let mut returned: u32 = 0;
                let hr = unsafe {
                    let f: FnEnumNext = transmute(slot(en.0, IDX_ENUM_NEXT));
                    f(en.0, -1, 1, &mut obj_ptr, &mut returned)
                };
                if hr < 0 || returned == 0 || obj_ptr.is_null() {
                    break;
                }
                let obj = Com(obj_ptr);
                result.push(read_object(&obj));
            }
            Ok(result)
        }
    }

    fn read_object(obj: &Com) -> Vec<(String, String)> {
        let mut props = Vec::new();
        let hr = unsafe {
            let f: FnBeginEnum = transmute(slot(obj.0, IDX_OBJ_BEGIN_ENUMERATION));
            f(obj.0, WBEM_FLAG_NONSYSTEM_ONLY)
        };
        if hr < 0 {
            return props;
        }
        loop {
            let mut name: *mut u16 = null_mut();
            let mut v = Variant::empty();
            let hr = unsafe {
                let f: FnObjNext = transmute(slot(obj.0, IDX_OBJ_NEXT));
                f(obj.0, 0, &mut name, &mut v, null_mut(), null_mut())
            };
            if hr != 0 {
                break;
            }
            let n = bstr_to_string(name);
            if !name.is_null() {
                unsafe { SysFreeString(name) };
            }
            let val = variant_to_string(&v).trim().to_string();
            unsafe { VariantClear(&mut v) };
            props.push((n, val));
        }
        unsafe {
            let f: FnEndEnum = transmute(slot(obj.0, IDX_OBJ_END_ENUMERATION));
            f(obj.0);
        }
        props
    }
}

fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn obj_json(props: &[(String, String)]) -> String {
    let items: Vec<String> = props
        .iter()
        .map(|(k, v)| format!("{}:{}", json_escape(k), json_escape(v)))
        .collect();
    format!("{{{}}}", items.join(","))
}

fn arr_json(items: &[String]) -> String {
    format!("[{}]", items.join(","))
}

#[cfg(windows)]
const SINGLE_CLASSES: &[(&str, &str)] = &[
    ("baseboard", "Win32_BaseBoard"),
    ("bios", "Win32_BIOS"),
    ("os", "Win32_OperatingSystem"),
];

#[cfg(windows)]
const MULTI_CLASSES: &[(&str, &str)] = &[
    ("cpu", "Win32_Processor"),
    ("memorychip", "Win32_PhysicalMemory"),
    ("diskdrive", "Win32_DiskDrive"),
    ("netadapter", "Win32_NetworkAdapter"),
    ("display", "Win32_DesktopMonitor"),
    ("videoadapter", "Win32_VideoController"),
    ("sound", "Win32_SoundDevice"),
    ("useraccount", "Win32_UserAccount"),
    ("share", "Win32_Share"),
    ("printer", "Win32_Printer"),
    ("product", "Win32_Product"),
    ("fixupdate", "Win32_QuickFixEngineering"),
];

#[cfg(windows)]
fn wmi_ref_name(path: &str) -> String {
    match path.rfind("Name=\"") {
        Some(p) => {
            let rest = &path[p + 6..];
            match rest.find('"') {
                Some(e) => rest[..e].to_string(),
                None => rest.to_string(),
            }
        }
        None => String::new(),
    }
}

#[cfg(windows)]
fn collect() -> Result<String, String> {
    use std::collections::BTreeMap;

    let w = wmi::Wmi::open().map_err(|e| format!("WMI: {}", e))?;
    let list = |wql: &str| -> Vec<Vec<(String, String)>> {
        match w.query(wql) {
            Ok(v) => v,
            Err(e) => {
                log(&format!("WMI query '{}' failed: {}", wql, e));
                Vec::new()
            }
        }
    };

    let mut parts: Vec<String> = Vec::new();

    for (key, class) in SINGLE_CLASSES {
        let rows = list(&format!("SELECT * FROM {}", class));
        let json = rows
            .first()
            .map(|o| obj_json(o))
            .unwrap_or_else(|| "{}".to_string());
        parts.push(format!("{}:{}", json_escape(key), json));
    }

    for (key, class) in MULTI_CLASSES {
        let rows = list(&format!("SELECT * FROM {}", class));
        let items: Vec<String> = rows.iter().map(|o| obj_json(o)).collect();
        parts.push(format!("{}:{}", json_escape(key), arr_json(&items)));
    }

    let mut pairs: Vec<(String, String)> = Vec::new();
    for row in list("SELECT * FROM Win32_GroupUser") {
        let (mut group, mut user) = (String::new(), String::new());
        for (k, v) in &row {
            match k.as_str() {
                "GroupComponent" => group = wmi_ref_name(v),
                "PartComponent" => user = wmi_ref_name(v),
                _ => {}
            }
        }
        if !group.is_empty() && !user.is_empty() {
            pairs.push((group, user));
        }
    }

    let mut by_user: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (g, u) in &pairs {
        by_user.entry(u.clone()).or_default().push(g.clone());
    }
    let usergroup: Vec<String> = by_user
        .iter()
        .map(|(user, groups)| {
            let gj: Vec<String> = groups.iter().map(|g| json_escape(g)).collect();
            format!(
                "{{\"user\":{},\"groups\":{}}}",
                json_escape(user),
                arr_json(&gj)
            )
        })
        .collect();
    parts.push(format!("\"usergroup\":{}", arr_json(&usergroup)));

    let admin_group = list("SELECT Name FROM Win32_Group WHERE SID='S-1-5-32-544'")
        .first()
        .and_then(|row| {
            row.iter()
                .find(|(k, _)| k == "Name")
                .map(|(_, v)| v.clone())
        })
        .unwrap_or_default();
    let admins: Vec<String> = if admin_group.is_empty() {
        Vec::new()
    } else {
        pairs
            .iter()
            .filter(|(g, _)| *g == admin_group)
            .map(|(_, u)| json_escape(u))
            .collect()
    };
    parts.push(format!("\"useradmin\":{}", arr_json(&admins)));

    Ok(format!("{{{}}}", parts.join(",")))
}

#[cfg(not(windows))]
fn collect() -> Result<String, String> {
    Err("сбор данных WMI поддерживается только в Windows".to_string())
}

struct Url {
    https: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse_url(s: &str) -> Result<Url, String> {
    let (https, rest) = if let Some(r) = s.strip_prefix("http://") {
        (false, r)
    } else if let Some(r) = s.strip_prefix("https://") {
        (true, r)
    } else {
        return Err(format!(
            "invalid URL '{}': expected http:// or https:// scheme",
            s
        ));
    };
    let (auth, path) = match rest.find('/') {
        Some(p) => (&rest[..p], rest[p..].to_string()),
        None => (rest, "/".to_string()),
    };
    if auth.is_empty() || auth.contains('@') {
        return Err(format!("invalid URL '{}'", s));
    }
    let default = if https { 443 } else { 80 };
    let bad_port = || format!("invalid port in URL '{}'", s);
    let (host, port) = if let Some(stripped) = auth.strip_prefix('[') {
        let end = stripped
            .find(']')
            .ok_or_else(|| format!("invalid URL '{}'", s))?;
        let host = stripped[..end].to_string();
        let after = &stripped[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse::<u16>().map_err(|_| bad_port())?,
            None => default,
        };
        (host, port)
    } else if let Some((h, p)) = auth.rsplit_once(':') {
        (h.to_string(), p.parse::<u16>().map_err(|_| bad_port())?)
    } else {
        (auth.to_string(), default)
    };
    if host.is_empty() {
        return Err(format!("malformed URL '{}'", s));
    }
    Ok(Url {
        https,
        host,
        port,
        path,
    })
}

fn find_subslice(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn dechunk(mut d: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(p) = find_subslice(d, b"\r\n") else {
            break;
        };
        let line = String::from_utf8_lossy(&d[..p]).to_string();
        let size_str = line.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(size_str, 16) else {
            break;
        };
        d = &d[p + 2..];
        if size == 0 {
            break;
        }
        if d.len() < size {
            out.extend_from_slice(d);
            break;
        }
        out.extend_from_slice(&d[..size]);
        d = &d[size..];
        if d.starts_with(b"\r\n") {
            d = &d[2..];
        }
    }
    out
}

type HttpResult = Result<(u16, String, String), String>;

fn post_http(u: &Url, body: &str, timeout: Duration) -> HttpResult {
    let addrs = (u.host.as_str(), u.port)
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve hostname {}: {}", u.host, e))?;
    let mut stream = None;
    let mut last_err = String::from("нет адресов");
    for a in addrs {
        match TcpStream::connect_timeout(&a, timeout) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    let mut stream = stream
        .ok_or_else(|| format!("failed to connect to {}:{}: {}", u.host, u.port, last_err))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let host_hdr = if u.host.contains(':') {
        format!("[{}]", u.host)
    } else {
        u.host.clone()
    };
    let host_hdr = if u.port == 80 {
        host_hdr
    } else {
        format!("{}:{}", host_hdr, u.port)
    };

    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}/{}\r\nAccept: */*\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        u.path,
        host_hdr,
        APP_NAME,
        VERSION,
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .map_err(|e| format!("request failed: {}", e))?;
    stream
        .write_all(body.as_bytes())
        .map_err(|e| format!("request failed: {}", e))?;
    let _ = stream.flush();

    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    if buf.is_empty() {
        return Err("empty server response".to_string());
    }

    let split = find_subslice(&buf, b"\r\n\r\n").ok_or("invalid HTTP response")?;
    let head = String::from_utf8_lossy(&buf[..split]).to_string();
    let body_bytes = &buf[split + 4..];
    let status_line = head.lines().next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let _ver = parts.next();
    let code = parts
        .next()
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or("malformed status line")?;
    let reason = parts.next().unwrap_or("").to_string();
    let chunked = head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked");
    let data = if chunked {
        dechunk(body_bytes)
    } else {
        body_bytes.to_vec()
    };
    Ok((code, reason, String::from_utf8_lossy(&data).to_string()))
}

fn post_https_curl(url: &str, body: &str, timeout: u64) -> HttpResult {
    let mut cmd = Command::new("curl.exe");
    cmd.args([
        "-sS",
        "-X",
        "POST",
        "-H",
        "Content-Type: application/json",
        "--data-binary",
        "@-",
        "--max-time",
        &timeout.to_string(),
        "-w",
        "\n%{http_code}",
        url,
    ])
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("HTTPS requires curl.exe (Windows 10+): {}", e))?;
    let mut stdin = child.stdin.take().ok_or("curl has no stdin")?;
    let data = body.as_bytes().to_vec();
    let writer = thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let out = child
        .wait_with_output()
        .map_err(|e| format!("curl error: {}", e))?;
    let _ = writer.join();

    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(format!("curl: {}", err));
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let (resp, code) = text.rsplit_once('\n').ok_or("invalid curl output")?;
    let code = code
        .trim()
        .parse::<u16>()
        .map_err(|_| "invalid curl response code")?;
    Ok((code, String::new(), resp.to_string()))
}

fn send(url: &str, body: &str, timeout: u64) -> HttpResult {
    let u = parse_url(url)?;
    if u.https {
        post_https_curl(url, body, timeout)
    } else {
        post_http(&u, body, Duration::from_secs(timeout))
    }
}

fn run_once(cfg: &Config) -> Result<(), String> {
    log("Collecting system information...");
    let body = collect()?;

    if cfg.dry_run {
        println!("{}", body);
        return Ok(());
    }

    let url = cfg.url.as_deref().ok_or("URL not specified")?;
    log(&format!(
        "Sending system information ({} bytes)...",
        body.len()
    ));
    let (code, reason, resp) = send(url, &body, cfg.timeout)?;
    log(&format!("Response information: {} {}", code, reason)
        .trim_end()
        .to_string());
    let resp = resp.trim();
    if !resp.is_empty() {
        log(&format!("Server response: {}", resp));
    }
    if (200..300).contains(&code) {
        Ok(())
    } else {
        Err(format!("server returned status {}", code))
    }
}

#[cfg(windows)]
mod winsvc {
    use super::*;
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicIsize, AtomicU32};

    const SERVICE_WIN32_OWN_PROCESS: u32 = 0x10;
    const SERVICE_STOPPED: u32 = 1;
    const SERVICE_START_PENDING: u32 = 2;
    const SERVICE_STOP_PENDING: u32 = 3;
    const SERVICE_RUNNING: u32 = 4;
    const ACCEPT_STOP: u32 = 0x1;
    const ACCEPT_SHUTDOWN: u32 = 0x4;
    const CTRL_STOP: u32 = 1;
    const CTRL_INTERROGATE: u32 = 4;
    const CTRL_SHUTDOWN: u32 = 5;
    const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
    const WAIT_TIMEOUT: u32 = 258;

    #[repr(C)]
    struct ServiceStatus {
        service_type: u32,
        current_state: u32,
        controls_accepted: u32,
        win32_exit_code: u32,
        service_specific_exit_code: u32,
        check_point: u32,
        wait_hint: u32,
    }

    #[repr(C)]
    struct ServiceTableEntryW {
        name: *const u16,
        proc_: Option<unsafe extern "system" fn(u32, *mut *mut u16)>,
    }

    type HandlerEx = unsafe extern "system" fn(u32, u32, *mut c_void, *mut c_void) -> u32;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn StartServiceCtrlDispatcherW(table: *const ServiceTableEntryW) -> i32;
        fn RegisterServiceCtrlHandlerExW(
            name: *const u16,
            handler: Option<HandlerEx>,
            ctx: *mut c_void,
        ) -> isize;
        fn SetServiceStatus(handle: isize, status: *const ServiceStatus) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateEventW(attr: *mut c_void, manual: i32, initial: i32, name: *const u16) -> isize;
        fn SetEvent(h: isize) -> i32;
        fn WaitForSingleObject(h: isize, ms: u32) -> u32;
        fn CloseHandle(h: isize) -> i32;
    }

    static SVC_CFG: OnceLock<Config> = OnceLock::new();
    static STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);
    static STOP_EVENT: AtomicIsize = AtomicIsize::new(0);
    static CHECKPOINT: AtomicU32 = AtomicU32::new(1);

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn set_status(state: u32, accepted: u32, exit_code: u32, wait_hint: u32) {
        let h = STATUS_HANDLE.load(Ordering::SeqCst);
        if h == 0 {
            return;
        }
        let pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
        let st = ServiceStatus {
            service_type: SERVICE_WIN32_OWN_PROCESS,
            current_state: state,
            controls_accepted: if pending { 0 } else { accepted },
            win32_exit_code: exit_code,
            service_specific_exit_code: 0,
            check_point: if pending {
                CHECKPOINT.fetch_add(1, Ordering::SeqCst)
            } else {
                0
            },
            wait_hint,
        };
        unsafe {
            SetServiceStatus(h, &st);
        }
    }

    unsafe extern "system" fn ctrl_handler(
        ctrl: u32,
        _event_type: u32,
        _data: *mut c_void,
        _ctx: *mut c_void,
    ) -> u32 {
        match ctrl {
            CTRL_STOP | CTRL_SHUTDOWN => {
                set_status(SERVICE_STOP_PENDING, 0, 0, 30_000);
                let ev = STOP_EVENT.load(Ordering::SeqCst);
                if ev != 0 {
                    unsafe { SetEvent(ev) };
                }
                0
            }
            CTRL_INTERROGATE => 0,
            _ => ERROR_CALL_NOT_IMPLEMENTED,
        }
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let cfg = match SVC_CFG.get() {
            Some(c) => c,
            None => return,
        };
        let name = wide(&cfg.name);
        let h =
            unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(ctrl_handler), null_mut()) };
        if h == 0 {
            log(&format!(
                "RegisterServiceCtrlHandlerEx failed: {}",
                std::io::Error::last_os_error()
            ));
            return;
        }
        STATUS_HANDLE.store(h, Ordering::SeqCst);
        set_status(SERVICE_START_PENDING, 0, 0, 5_000);

        let ev = unsafe { CreateEventW(null_mut(), 1, 0, null()) };
        STOP_EVENT.store(ev, Ordering::SeqCst);

        set_status(SERVICE_RUNNING, ACCEPT_STOP | ACCEPT_SHUTDOWN, 0, 0);
        log(&format!(
            "Service '{}' started (interval {} s, url {})",
            cfg.name,
            cfg.interval,
            cfg.url.as_deref().unwrap_or("-")
        ));

        let wait_ms = cfg.interval.saturating_mul(1000).min(u32::MAX as u64 - 1) as u32;
        loop {
            if let Err(e) = run_once(cfg) {
                log(&format!("Error: {}", e));
            }
            if unsafe { WaitForSingleObject(ev, wait_ms) } != WAIT_TIMEOUT {
                break;
            }
        }

        log("Service stopped");
        set_status(SERVICE_STOPPED, 0, 0, 0);
        unsafe { CloseHandle(ev) };
    }

    pub fn run_as_service(cfg: &Config) -> Result<(), String> {
        let _ = SVC_CFG.set(cfg.clone());
        SERVICE_MODE.store(true, Ordering::SeqCst);
        let name = wide(&cfg.name);
        let table = [
            ServiceTableEntryW {
                name: name.as_ptr(),
                proc_: Some(service_main),
            },
            ServiceTableEntryW {
                name: null(),
                proc_: None,
            },
        ];
        let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
        if ok == 0 {
            return Err(format!(
                "StartServiceCtrlDispatcher: {} (the --service flag is intended for SCM use only)",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
use winsvc::run_as_service;

#[cfg(not(windows))]
fn run_as_service(_cfg: &Config) -> Result<(), String> {
    Err("service mode is only supported on Windows".to_string())
}

fn sc(args: &[&str]) -> Result<bool, String> {
    Command::new("sc.exe")
        .args(args)
        .status()
        .map(|s| s.success())
        .map_err(|e| format!("failed to execute sc.exe: {}", e))
}

fn install_service(cfg: &Config) -> Result<(), String> {
    let url = cfg.url.as_deref().ok_or("URL not specified")?;
    let exe =
        env::current_exe().map_err(|e| format!("failed to determine executable path: {}", e))?;
    let bin_path = format!(
        "\"{}\" --service --url \"{}\" --interval {} --timeout {} --name \"{}\"",
        exe.display(),
        url,
        cfg.interval,
        cfg.timeout,
        cfg.name
    );
    let display = format!("PC SysInspector Agent ({})", cfg.name);

    if !sc(&[
        "create",
        &cfg.name,
        "binPath=",
        &bin_path,
        "start=",
        "auto",
        "DisplayName=",
        &display,
    ])? {
        return Err("failed to create service (are you running as administrator?)".to_string());
    }
    let _ = sc(&[
        "description",
        &cfg.name,
        "Collects system information and sends it to a server",
    ]);
    let _ = sc(&[
        "failure",
        &cfg.name,
        "reset=",
        "86400",
        "actions=",
        "restart/60000/restart/60000/restart/60000",
    ]);
    println!(
        "Service '{}' installed. To start it, run: {} --start --name \"{}\"",
        cfg.name, BIN_NAME, cfg.name
    );
    Ok(())
}

fn uninstall_service(cfg: &Config) -> Result<(), String> {
    let _ = sc(&["stop", &cfg.name]);
    thread::sleep(Duration::from_secs(2));
    if sc(&["delete", &cfg.name])? {
        Ok(())
    } else {
        Err("failed to remove service".to_string())
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (action, cfg) = match parse_args(&args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "{}: {}\nFor more information, run: {} --help",
                BIN_NAME, e, BIN_NAME
            );
            return ExitCode::from(2);
        }
    };

    let result: Result<(), String> = match action {
        Action::Help => {
            print_help();
            Ok(())
        }
        Action::Version => {
            print_version();
            Ok(())
        }
        Action::Service => run_as_service(&cfg),
        Action::Install => install_service(&cfg),
        Action::Uninstall => uninstall_service(&cfg),
        Action::Start => sc(&["start", &cfg.name]).and_then(|ok| {
            if ok {
                Ok(())
            } else {
                Err("failed to start service".to_string())
            }
        }),
        Action::Stop => sc(&["stop", &cfg.name]).and_then(|ok| {
            if ok {
                Ok(())
            } else {
                Err("failed to stop service".to_string())
            }
        }),
        Action::Run => {
            if cfg.dry_run {
                LOG_STDERR.store(true, Ordering::Relaxed);
            }
            log(&format!("PC SysInspector Agent [Version {}]", VERSION));
            log(&format!(
                "(c) Helpdesk {}. All rights reserved.",
                current_year()
            ));
            log("");
            run_once(&cfg)
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if SERVICE_MODE.load(Ordering::Relaxed) {
                log(&format!("Fatal: {}", e));
            } else {
                eprintln!("Error: {}", e);
            }
            ExitCode::FAILURE
        }
    }
}

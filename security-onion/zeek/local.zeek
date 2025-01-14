# Zeek local.zeek — Custom Scripts for Security Onion 2.4
# Loaded by: zeekctl deploy → processes/local.zeek
# Scripts: payment protocol logging, SSL/TLS certificate monitoring
# MITRE: T1041, T1573, T1190, T1071.001

@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/dns
@load base/frameworks/notice
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssl/log-hostnames
@load policy/protocols/http/detect-sqli

# ---------------------------------------------------------------------------
# PCI: Payment protocol field logging
# Logs HTTP POSTs to known payment endpoints with sanitized PAN prefix
# MITRE: T1041 — Exfiltration Over C2 Channel
# ---------------------------------------------------------------------------
module PaymentProto;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:          time    &log;
        uid:         string  &log;
        src_ip:      addr    &log;
        dst_ip:      addr    &log;
        dst_port:    port    &log;
        method:      string  &log &optional;
        host:        string  &log &optional;
        uri:         string  &log &optional;
        pan_prefix:  string  &log &optional;   # first 6 digits only (BIN)
        has_cvv:     bool    &log &default=F;
        has_track:   bool    &log &default=F;
    };
}

event zeek_init() &priority=5 {
    Log::create_stream(PaymentProto::LOG, [$columns=Info, $path="payment_proto"]);
}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) {
    if (!is_orig) return;
    if (!c?$http) return;

    local body = "";
    if (c$http?$post_body) body = c$http$post_body;

    local is_payment = F;
    local pan_pfx = "";
    local cvv_found = F;
    local track_found = F;

    # Detect Visa/MC PAN prefix (first 6 digits — BIN range, non-sensitive)
    if (/4[0-9]{5}/ in body || /5[1-5][0-9]{4}/ in body) {
        is_payment = T;
        # Extract BIN only — do not log full PAN
        pan_pfx = sub(body, /.*([45][0-9]{5}).*/i, "\\1");
    }

    # Detect CVV field presence (key name only, not value)
    if (/["\']cvv["\']\s*:/ in body || /cvv2=/i in body) {
        cvv_found = T;
        is_payment = T;
    }

    # Detect Track 2 pattern
    if (/;[0-9]{13,19}=[0-9]{4}/ in body) {
        track_found = T;
        is_payment = T;
    }

    if (is_payment) {
        Log::write(PaymentProto::LOG, Info(
            $ts        = network_time(),
            $uid       = c$uid,
            $src_ip    = c$id$orig_h,
            $dst_ip    = c$id$resp_h,
            $dst_port  = c$id$resp_p,
            $method    = c$http?$method ? c$http$method : "",
            $host      = c$http?$host   ? c$http$host   : "",
            $uri       = c$http?$uri    ? c$http$uri     : "",
            $pan_prefix = pan_pfx,
            $has_cvv   = cvv_found,
            $has_track = track_found
        ));

        # Raise notice for cleartext payment data
        if (!is_ssl(c)) {
            NOTICE([$note=Notice::Weird,
                    $conn=c,
                    $msg="Payment fields detected in cleartext HTTP",
                    $sub=fmt("has_cvv=%s has_track=%s bin=%s", cvv_found, track_found, pan_pfx)]);
        }
    }
}

# ---------------------------------------------------------------------------
# SSL/TLS: Self-signed and expiring certificate monitoring
# MITRE: T1573.002 — Encrypted Channel: Asymmetric Cryptography
#        T1071.001 — Application Layer Protocol: Web Protocols
# ---------------------------------------------------------------------------
module SSLCertMonitor;

export {
    redef enum Notice::Type += {
        Self_Signed_Non_Standard_Port,
        Cert_Expiring_Soon,
        Weak_Cipher_Detected,
    };

    const STANDARD_TLS_PORTS: set[port] = {443/tcp, 8443/tcp, 8080/tcp} &redef;
    const EXPIRY_WARN_DAYS = 14 &redef;
}

event ssl_established(c: connection) {
    if (!c?$ssl) return;

    local dst_port = c$id$resp_p;

    # Alert: self-signed cert on non-standard port (potential C2)
    if (c$ssl?$validation_status &&
        "self signed" in c$ssl$validation_status &&
        dst_port !in STANDARD_TLS_PORTS) {
        NOTICE([$note=SSLCertMonitor::Self_Signed_Non_Standard_Port,
                $conn=c,
                $msg=fmt("Self-signed TLS cert on port %s", dst_port),
                $sub=c$ssl?$server_name ? c$ssl$server_name : "-",
                $identifier=cat(c$id$orig_h, c$id$resp_h, dst_port)]);
    }

    # Alert: certificate expiring within threshold
    if (c$ssl?$cert_chain && |c$ssl$cert_chain| > 0) {
        local leaf = c$ssl$cert_chain[0];
        if (leaf?$x509 && leaf$x509?$certificate) {
            local not_after = leaf$x509$certificate$not_valid_after;
            local days_left = (not_after - network_time()) / 1day;
            if (days_left < EXPIRY_WARN_DAYS) {
                NOTICE([$note=SSLCertMonitor::Cert_Expiring_Soon,
                        $conn=c,
                        $msg=fmt("TLS cert expires in %.0f days", days_left),
                        $sub=c$ssl?$server_name ? c$ssl$server_name : "-"]);
            }
        }
    }
}

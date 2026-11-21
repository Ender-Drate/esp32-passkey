package io.github.enderdrate.techxpasskey;

import android.Manifest;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

import io.github.enderdrate.techxpasskey.ble.BleClient;
import io.github.enderdrate.techxpasskey.ctap.CtapClient;
import io.github.enderdrate.techxpasskey.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    private ActivityMainBinding b;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final List<CtapClient.Credential> credentials = new ArrayList<>();

    private BleClient ble;
    private CtapClient ctap;
    private CtapClient.Info info;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        b = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(b.getRoot());

        b.connectButton.setOnClickListener(v -> {
            if (ble != null && ble.isConnected()) {
                disconnect();
            } else {
                connect();
            }
        });
        b.pinButton.setOnClickListener(v -> changeOrSetPin());
        b.refreshCredsButton.setOnClickListener(v -> refreshCredentials());

        log("TechXPassKey 伴侣 App 已启动");
        log("通过 BLE 连接设备，支持 PIN 与凭据管理");
        ensurePermissions();
    }

    // ------------------------------------------------------------ permissions
    private String[] requiredPermissions() {
        if (Build.VERSION.SDK_INT >= 31) {
            return new String[]{Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT};
        }
        return new String[]{Manifest.permission.ACCESS_FINE_LOCATION};
    }

    private boolean hasPermissions() {
        for (String p : requiredPermissions()) {
            if (ContextCompat.checkSelfPermission(this, p) != PackageManager.PERMISSION_GRANTED) {
                return false;
            }
        }
        return true;
    }

    private void ensurePermissions() {
        if (!hasPermissions()) {
            requestPermissions(requiredPermissions(), 1);
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        boolean ok = grantResults.length > 0;
        for (int g : grantResults) {
            if (g != PackageManager.PERMISSION_GRANTED) ok = false;
        }
        if (ok) {
            log("蓝牙权限已授予");
        } else {
            log("蓝牙权限被拒绝，无法扫描设备");
            toast("需要蓝牙权限才能连接设备");
        }
    }

    // --------------------------------------------------------------- connect
    private void connect() {
        if (!hasPermissions()) {
            ensurePermissions();
            return;
        }
        setBusy(true);
        setStatus("正在扫描 TechXPassKey…", false);
        worker.execute(() -> {
            try {
                closeBle();
                BleClient client = new BleClient(this, new BleClient.Listener() {
                    @Override
                    public void onDisconnected() {
                        main.post(() -> {
                            if (ble != null) ble = null;
                            ctap = null;
                            info = null;
                            credentials.clear();
                            renderCredentials();
                            setStatus("未连接", false);
                            b.connectButton.setText("扫描并连接");
                            setBusy(false);
                        });
                    }

                    @Override
                    public void onLog(String line) {
                        log(line);
                    }
                });
                client.scanAndConnect(20000);
                CtapClient api = new CtapClient(client);
                CtapClient.Info loaded = api.getInfo();
                ble = client;
                ctap = api;
                info = loaded;
                main.post(() -> {
                    updateInfo();
                    b.connectButton.setText("断开");
                    setStatus("已连接 · " + (loaded.pinSet() ? "PIN 已设置" : "未设置 PIN"), true);
                    setBusy(false);
                    refreshCredentials();
                });
            } catch (Exception e) {
                log("连接失败: " + message(e));
                main.post(() -> {
                    setStatus("未连接", false);
                    b.connectButton.setText("扫描并连接");
                    setBusy(false);
                    toast(message(e));
                });
            }
        });
    }

    private void disconnect() {
        worker.execute(this::closeBle);
        setStatus("未连接", false);
        b.connectButton.setText("扫描并连接");
        info = null;
        credentials.clear();
        renderCredentials();
        clearInfo();
    }

    private void closeBle() {
        if (ble != null) {
            ble.close();
            ble = null;
        }
        ctap = null;
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        closeBle();
        worker.shutdownNow();
    }

    // ------------------------------------------------------------------- PIN
    private void changeOrSetPin() {
        if (ctap == null || info == null) {
            toast("请先连接设备");
            return;
        }
        String current = b.pinCurrent.getText().toString();
        String next = b.pinNew.getText().toString();
        if (next.length() < info.minPinLength) {
            toast("新 PIN 至少 " + info.minPinLength + " 位");
            return;
        }
        setBusy(true);
        worker.execute(() -> {
            try {
                if (info.pinSet()) {
                    ctap.changePin(current, next);
                    log("PIN 已修改");
                } else {
                    ctap.setPin(next);
                    log("PIN 已设置");
                }
                CtapClient.Info refreshed = ctap.getInfo();
                info = refreshed;
                main.post(() -> {
                    b.pinCurrent.setText("");
                    b.pinNew.setText("");
                    updateInfo();
                    setStatus("已连接 · PIN 已设置", true);
                    setBusy(false);
                    toast("PIN 已更新");
                });
            } catch (Exception e) {
                log("PIN 操作失败: " + message(e));
                main.post(() -> {
                    setBusy(false);
                    toast(message(e));
                });
            }
        });
    }

    // ------------------------------------------------------------ credentials
    private void refreshCredentials() {
        if (ctap == null || info == null) {
            toast("请先连接设备");
            return;
        }
        if (info.pinSet()) {
            String pin = b.pinCurrent.getText().toString();
            if (pin.isEmpty()) {
                askPin(this::loadCredentials);
                return;
            }
            loadCredentials(pin);
        } else {
            loadCredentials("");
        }
    }

    private void loadCredentials(String pin) {
        setBusy(true);
        worker.execute(() -> {
            try {
                List<CtapClient.Credential> list = ctap.listCredentials(pin);
                credentials.clear();
                credentials.addAll(list);
                log("读取凭据: " + list.size() + " 个");
                main.post(() -> {
                    renderCredentials();
                    setBusy(false);
                });
            } catch (Exception e) {
                log("读取凭据失败: " + message(e));
                main.post(() -> {
                    setBusy(false);
                    toast(message(e));
                });
            }
        });
    }

    private void renderCredentials() {
        b.credContainer.removeAllViews();
        if (credentials.isEmpty()) {
            TextView empty = new TextView(this);
            empty.setText("没有凭据");
            empty.setTextColor(ContextCompat.getColor(this, R.color.ink3));
            empty.setTextSize(14);
            empty.setPadding(0, dp(14), 0, dp(14));
            b.credContainer.addView(empty);
            return;
        }
        for (int i = 0; i < credentials.size(); i++) {
            CtapClient.Credential c = credentials.get(i);
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(0, dp(12), 0, dp(12));

            LinearLayout text = new LinearLayout(this);
            text.setOrientation(LinearLayout.VERTICAL);
            text.setLayoutParams(new LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            TextView rp = new TextView(this);
            rp.setText(c.rpId);
            rp.setTextSize(15);
            rp.setTextColor(ContextCompat.getColor(this, R.color.ink));
            rp.setTypeface(Typeface.DEFAULT_BOLD);
            TextView user = new TextView(this);
            String label = c.userName.isEmpty() ? c.displayName : c.userName;
            user.setText(label.isEmpty() ? "未命名用户" : label);
            user.setTextSize(13);
            user.setTextColor(ContextCompat.getColor(this, R.color.ink2));
            text.addView(rp);
            text.addView(user);

            TextView delete = new TextView(this);
            delete.setText("删除");
            delete.setTextSize(14);
            delete.setTextColor(ContextCompat.getColor(this, R.color.link));
            delete.setPadding(dp(16), dp(4), 0, dp(4));
            delete.setOnClickListener(v -> confirmDelete(c));
            row.addView(text);
            row.addView(delete);
            b.credContainer.addView(row);

            if (i < credentials.size() - 1) addDivider(b.credContainer);
        }
    }

    private void confirmDelete(CtapClient.Credential c) {
        new AlertDialog.Builder(this)
                .setTitle("删除这个 Passkey？")
                .setMessage(c.rpId + "\n删除后该网站将无法再用这块设备登录。")
                .setNegativeButton("取消", null)
                .setPositiveButton("删除", (d, w) -> withPin(pin -> deleteCredential(c, pin)))
                .show();
    }

    private void deleteCredential(CtapClient.Credential c, String pin) {
        setBusy(true);
        worker.execute(() -> {
            try {
                ctap.deleteCredential(pin, c.credId);
                log("已删除凭据: " + c.rpId);
                List<CtapClient.Credential> list = ctap.listCredentials(pin);
                credentials.clear();
                credentials.addAll(list);
                main.post(() -> {
                    renderCredentials();
                    setBusy(false);
                    toast("已删除");
                });
            } catch (Exception e) {
                log("删除失败: " + message(e));
                main.post(() -> {
                    setBusy(false);
                    toast(message(e));
                });
            }
        });
    }

    private void withPin(Consumer<String> action) {
        if (info != null && info.pinSet()) {
            String pin = b.pinCurrent.getText().toString();
            if (pin.isEmpty()) {
                askPin(action);
            } else {
                action.accept(pin);
            }
        } else {
            action.accept("");
        }
    }

    private void askPin(Consumer<String> action) {
        EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        input.setHint("设备 PIN");
        int pad = dp(20);
        input.setPadding(pad, pad, pad, pad);
        new AlertDialog.Builder(this)
                .setTitle("输入设备 PIN")
                .setView(input)
                .setNegativeButton("取消", null)
                .setPositiveButton("确定", (DialogInterface d, int w) -> {
                    String pin = input.getText().toString();
                    if (pin.isEmpty()) {
                        toast("PIN 不能为空");
                    } else {
                        action.accept(pin);
                    }
                })
                .show();
    }

    // -------------------------------------------------------------------- UI
    private void updateInfo() {
        if (info == null) {
            clearInfo();
            return;
        }
        b.deviceHint.setVisibility(View.GONE);
        clearInfo();
        addInfoRow("固件", firmware(info.firmwareVersion));
        addInfoRow("AAGUID", hex(info.aaguid));
        addInfoRow("PIN", info.pinSet() ? "已设置" : "未设置");
        addInfoRow("剩余容量", String.valueOf(info.remaining) + " 个凭据");
        addInfoRow("传输", info.transports.isEmpty() ? "BLE" : String.join(" · ", info.transports));
        addInfoRow("协议", String.join(" · ", info.versions));
        addInfoRow("最大消息", info.maxMsgSize + " 字节");
    }

    private void clearInfo() {
        b.infoContainer.removeAllViews();
        b.deviceHint.setVisibility(View.VISIBLE);
    }

    private void addInfoRow(String label, String value) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setPadding(0, dp(9), 0, dp(9));
        TextView l = new TextView(this);
        l.setText(label);
        l.setTextSize(13);
        l.setTextColor(ContextCompat.getColor(this, R.color.ink2));
        l.setLayoutParams(new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        TextView v = new TextView(this);
        v.setText(value);
        v.setTextSize(14);
        v.setTextColor(ContextCompat.getColor(this, R.color.ink));
        v.setGravity(Gravity.END);
        row.addView(l);
        row.addView(v);
        b.infoContainer.addView(row);
        addDivider(b.infoContainer);
    }

    private void addDivider(LinearLayout parent) {
        View line = new View(this);
        line.setBackgroundColor(ContextCompat.getColor(this, R.color.line));
        parent.addView(line, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(1)));
    }

    private void setStatus(String text, boolean connected) {
        b.statusText.setText(text);
        b.statusDot.setBackgroundResource(connected ? R.drawable.dot_on : R.drawable.dot_off);
    }

    private void setBusy(boolean busy) {
        b.connectButton.setEnabled(!busy || (ble != null && ble.isConnected()));
        b.pinButton.setEnabled(!busy);
        b.refreshCredsButton.setEnabled(!busy);
    }

    private void log(String line) {
        main.post(() -> {
            String time = new java.text.SimpleDateFormat("HH:mm:ss", Locale.getDefault())
                    .format(new java.util.Date());
            b.logText.append("[" + time + "] " + line + "\n");
            View parent = (View) b.logText.getParent();
            if (parent instanceof android.widget.ScrollView) {
                ((android.widget.ScrollView) parent).fullScroll(View.FOCUS_DOWN);
            }
        });
    }

    private void toast(String message) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
    }

    private static String message(Exception e) {
        return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
    }

    private static String firmware(long version) {
        return String.format(Locale.US, "%d.%d.%d",
                (version >> 16) & 0xFF, (version >> 8) & 0xFF, version & 0xFF);
    }

    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte x : data) {
            if (sb.length() > 0) sb.append(' ');
            sb.append(String.format("%02X", x));
        }
        return sb.toString();
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}

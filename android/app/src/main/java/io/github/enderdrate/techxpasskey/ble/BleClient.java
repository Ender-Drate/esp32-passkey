package io.github.enderdrate.techxpasskey.ble;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.os.Build;

import java.io.IOException;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * FIDO BLE transport: GATT 0xFFFD, F1D0FFF1 control point, F1D0FFF2 status.
 * All CTAP calls run on a worker thread and block on latches; BLE callbacks
 * complete them.
 */
public class BleClient {

    public interface Listener {
        void onDisconnected();

        void onLog(String line);
    }

    public static final UUID SERVICE = UUID.fromString("0000fffd-0000-1000-8000-00805f9b34fb");
    public static final UUID CP = UUID.fromString("f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb");
    public static final UUID STATUS = UUID.fromString("f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb");
    public static final UUID CP_LEN = UUID.fromString("f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb");
    private static final UUID CCCD = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");

    private final Context context;
    private final Listener listener;
    private BluetoothAdapter adapter;
    private BluetoothGatt gatt;
    private BluetoothGattCharacteristic cp;
    private BluetoothGattCharacteristic status;
    private BluetoothGattCharacteristic cpLen;

    private volatile boolean connected = false;
    private volatile int mtu = 23;
    private volatile int maxWrite = 20;

    private CountDownLatch scanLatch;
    private CountDownLatch connectLatch;
    private CountDownLatch servicesLatch;
    private CountDownLatch descLatch;
    private CountDownLatch writeLatch;
    private CountDownLatch readLatch;
    private CountDownLatch mtuLatch;
    private CountDownLatch responseLatch;

    private volatile BluetoothDevice foundDevice;
    private volatile byte[] readValue;
    private volatile byte[] response;
    private volatile int responseStat;

    private int rxTotal = 0;
    private int rxGot = 0;
    private int rxSeq = 0;
    private byte[] rxBody;

    public BleClient(Context context, Listener listener) {
        this.context = context.getApplicationContext();
        this.listener = listener;
        BluetoothManager manager =
                (BluetoothManager) this.context.getSystemService(Context.BLUETOOTH_SERVICE);
        adapter = manager != null ? manager.getAdapter() : null;
    }

    public boolean isConnected() {
        return connected;
    }

    // ------------------------------------------------------------- discovery
    public void scanAndConnect(long timeoutMs) throws IOException {
        if (adapter == null) throw new IOException("本机没有蓝牙适配器");
        if (!adapter.isEnabled()) throw new IOException("请先打开蓝牙");
        BluetoothLeScanner scanner = adapter.getBluetoothLeScanner();
        if (scanner == null) throw new IOException("BLE 扫描不可用");

        foundDevice = null;
        scanLatch = new CountDownLatch(1);
        ScanCallback callback = new ScanCallback() {
            @Override
            public void onScanResult(int callbackType, ScanResult result) {
                BluetoothDevice device = result.getDevice();
                String name = null;
                try {
                    name = device.getName();
                } catch (SecurityException ignored) {
                }
                boolean matches = name != null && name.contains("TechXPassKey");
                if (!matches && result.getScanRecord() != null
                        && result.getScanRecord().getServiceUuids() != null) {
                    matches = result.getScanRecord().getServiceUuids()
                            .contains(new android.os.ParcelUuid(SERVICE));
                }
                if (matches) {
                    foundDevice = device;
                    scanLatch.countDown();
                }
            }

            @Override
            public void onScanFailed(int errorCode) {
                log("扫描失败: " + errorCode);
                scanLatch.countDown();
            }
        };

        ScanSettings settings = new ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .build();
        scanner.startScan(null, settings, callback);
        try {
            boolean found;
            try {
                found = scanLatch.await(timeoutMs, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                throw new IOException("扫描被中断");
            }
            if (!found || foundDevice == null) {
                throw new IOException("没有找到 TechXPassKey，请确认设备已上电并在附近");
            }
        } finally {
            scanner.stopScan(callback);
        }
        log("找到设备 " + foundDevice.getAddress());

        connectLatch = new CountDownLatch(1);
        servicesLatch = new CountDownLatch(1);
        gatt = foundDevice.connectGatt(context, false, gattCallback,
                BluetoothDevice.TRANSPORT_LE);
        if (gatt == null) throw new IOException("connectGatt 失败");
        try {
            if (!connectLatch.await(15, TimeUnit.SECONDS)) throw new IOException("连接超时");
            if (!connected) throw new IOException("连接被拒绝");
            if (!servicesLatch.await(15, TimeUnit.SECONDS)) throw new IOException("GATT 服务发现超时");
        } catch (InterruptedException e) {
            throw new IOException("连接被中断");
        }
        setupCharacteristics();
    }

    private void setupCharacteristics() throws IOException {
        BluetoothGattService service = gatt.getService(SERVICE);
        if (service == null) throw new IOException("设备没有 FIDO 服务 0xFFFD");
        cp = service.getCharacteristic(CP);
        status = service.getCharacteristic(STATUS);
        cpLen = service.getCharacteristic(CP_LEN);
        if (cp == null || status == null) throw new IOException("FIDO 特征缺失");

        if (!gatt.setCharacteristicNotification(status, true)) {
            throw new IOException("无法订阅状态通知");
        }
        BluetoothGattDescriptor descriptor = status.getDescriptor(CCCD);
        if (descriptor != null) {
            descLatch = new CountDownLatch(1);
            descriptor.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
            if (!gatt.writeDescriptor(descriptor)) throw new IOException("写 CCCD 失败");
            try {
                descLatch.await(3, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
            }
        }

        mtuLatch = new CountDownLatch(1);
        try {
            gatt.requestMtu(517);
            mtuLatch.await(2, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }

        int len = 20;
        if (cpLen != null) {
            readLatch = new CountDownLatch(1);
            if (gatt.readCharacteristic(cpLen)) {
                try {
                    readLatch.await(3, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                }
            }
            if (readValue != null && readValue.length >= 2) {
                len = (readValue[0] & 0xFF) | ((readValue[1] & 0xFF) << 8);
            }
        }
        maxWrite = Math.max(20, Math.min(len, Math.max(20, mtu - 3)));
        log("已连接，MTU=" + mtu + "，单包=" + maxWrite + " 字节");
    }

    // ------------------------------------------------------------------ CTAP
    public synchronized byte[] call(int cmd, byte[] payload, long timeoutMs) throws IOException {
        if (!connected || gatt == null || cp == null) throw new IOException("设备未连接");
        response = null;
        responseStat = 0;
        rxTotal = 0;
        rxGot = 0;
        rxSeq = 0;
        responseLatch = new CountDownLatch(1);

        byte[] frame = new byte[3 + payload.length];
        frame[0] = (byte) cmd;
        frame[1] = (byte) ((payload.length >> 8) & 0xFF);
        frame[2] = (byte) (payload.length & 0xFF);
        System.arraycopy(payload, 0, frame, 3, payload.length);

        int first = Math.min(maxWrite, frame.length);
        writeSync(Arrays.copyOfRange(frame, 0, first));
        int sent = first;
        int seq = 0;
        while (sent < frame.length) {
            int n = Math.min(maxWrite - 1, frame.length - sent);
            byte[] packet = new byte[1 + n];
            packet[0] = (byte) (seq & 0x7F);
            System.arraycopy(frame, sent, packet, 1, n);
            seq = (seq + 1) & 0x7F;
            sent += n;
            writeSync(packet);
        }

        try {
            if (!responseLatch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                throw new IOException("等待设备响应超时");
            }
        } catch (InterruptedException e) {
            throw new IOException("等待响应被中断");
        }        if (responseStat == 0xBF) {
            throw new IOException("BLE 传输错误: " + hex(response));
        }
        return response;
    }

    private void writeSync(byte[] data) throws IOException {
        writeLatch = new CountDownLatch(1);
        boolean ok;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            int result = gatt.writeCharacteristic(cp, data,
                    BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
            ok = result == android.bluetooth.BluetoothStatusCodes.SUCCESS;
        } else {
            cp.setValue(data);
            ok = gatt.writeCharacteristic(cp);
        }
        if (!ok) throw new IOException("BLE 写入被拒绝");
        try {
            if (!writeLatch.await(5, TimeUnit.SECONDS)) throw new IOException("BLE 写入超时");
        } catch (InterruptedException e) {
            throw new IOException("BLE 写入被中断");
        }
    }

    // -------------------------------------------------------------- callbacks
    private final BluetoothGattCallback gattCallback = new BluetoothGattCallback() {
        @Override
        public void onConnectionStateChange(BluetoothGatt g, int status, int newState) {
            if (newState == BluetoothGatt.STATE_CONNECTED) {
                connected = true;
                log("GATT 已连接，发现服务…");
                g.discoverServices();
                connectLatch.countDown();
            } else if (newState == BluetoothGatt.STATE_DISCONNECTED) {
                connected = false;
                log("GATT 已断开");
                connectLatch.countDown();
                listener.onDisconnected();
            }
        }

        @Override
        public void onServicesDiscovered(BluetoothGatt g, int status) {
            log("GATT 服务发现: " + (status == BluetoothGatt.GATT_SUCCESS ? "成功" : "失败 " + status));
            servicesLatch.countDown();
        }

        @Override
        public void onCharacteristicWrite(BluetoothGatt g, BluetoothGattCharacteristic c, int status) {
            if (writeLatch != null) writeLatch.countDown();
        }

        @Override
        public void onDescriptorWrite(BluetoothGatt g, BluetoothGattDescriptor d, int status) {
            if (descLatch != null) descLatch.countDown();
        }

        @Override
        public void onMtuChanged(BluetoothGatt g, int newMtu, int status) {
            if (status == BluetoothGatt.GATT_SUCCESS) mtu = newMtu;
            if (mtuLatch != null) mtuLatch.countDown();
        }

        @Override
        public void onCharacteristicRead(BluetoothGatt g, BluetoothGattCharacteristic c, int status) {
            readValue = c.getValue();
            if (readLatch != null) readLatch.countDown();
        }

        @Override
        public void onCharacteristicChanged(BluetoothGatt g, BluetoothGattCharacteristic c) {
            onNotification(c.getValue());
        }
    };

    private synchronized void onNotification(byte[] p) {
        if (p == null || p.length == 0) return;
        if (rxTotal == 0) {
            if (p.length < 3) return;
            responseStat = p[0] & 0xFF;
            if (responseStat == 0x82) return; // keepalive
            rxTotal = ((p[1] & 0xFF) << 8) | (p[2] & 0xFF);
            if (rxTotal <= 0 || rxTotal > 8192) {
                rxTotal = 0;
                return;
            }
            rxBody = new byte[rxTotal];
            rxGot = 0;
            rxSeq = 0;
            int n = Math.min(p.length - 3, rxTotal);
            System.arraycopy(p, 3, rxBody, 0, n);
            rxGot = n;
        } else {
            int seq = p[0] & 0x7F;
            if (seq != rxSeq) return;
            rxSeq = (rxSeq + 1) & 0x7F;
            int n = Math.min(p.length - 1, rxTotal - rxGot);
            System.arraycopy(p, 1, rxBody, rxGot, n);
            rxGot += n;
        }
        if (rxTotal > 0 && rxGot >= rxTotal) {
            response = rxBody;
            rxTotal = 0;
            if (responseLatch != null) responseLatch.countDown();
        }
    }

    public void close() {
        connected = false;
        try {
            if (gatt != null) {
                gatt.disconnect();
                gatt.close();
            }
        } catch (Exception ignored) {
        }
        gatt = null;
        cp = null;
        status = null;
    }

    private void log(String line) {
        listener.onLog(line);
    }

    private static String hex(byte[] data) {
        if (data == null) return "";
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}

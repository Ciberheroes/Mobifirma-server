package server;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.PublicKey;
import java.security.Signature;

import javax.net.ssl.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.json.JSONObject;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.text.SimpleDateFormat;

public class MsgSSLServerSocket {
	public static byte[] getBytesFromString(String cadenaStr) {
		String cadena = cadenaStr.replace("[", "").replace("]", "").replace("\r", "");

		String[] partes = cadena.split(", ");

		byte[] arrayBytes = new byte[partes.length];

		for (int i = 0; i < partes.length; i++) {
			arrayBytes[i] = Byte.parseByte(partes[i]);
		}

		return arrayBytes;
	}

	public static PublicKey getPublicKeyFromString(String cadena) throws Exception {

		byte[] arrayBytes = getBytesFromString(cadena);
		X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(arrayBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");

		return kf.generatePublic(X509publicKey);
	}

	/**
	 * @param args
	 * @throws IOException
	 * @throws InterruptedException
	 */
	public static void main(String[] args)
			throws IOException, InterruptedException, SQLException, ClassNotFoundException {

		loadEnvVariables();

		final String DB_URL = System.getProperty("DB_URL");
		final String CLIENT_PUBLIC_KEY = System.getProperty("CLIENT_PUBLIC_KEY");

		try {
			SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
			SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(Integer.valueOf(System.getProperty("PORT")));
			SSLParameters sslParameters = new SSLParameters();
			String[] enabledCipherSuites = System.getProperty("ENABLED_CIPHER_SUITES").split(",");
            sslParameters.setCipherSuites(enabledCipherSuites);
			serverSocket.setSSLParameters(sslParameters);

			System.out.println("Connecting to database...");
			final Connection conn = DriverManager.getConnection(DB_URL);

			System.out.println("Creating tables in given database...");
			Statement stmt = conn.createStatement();
			stmt.setQueryTimeout(30);

			String dropOrderDetailsTable = "DROP TABLE IF EXISTS ORDER_DETAILS";
			stmt.executeUpdate(dropOrderDetailsTable);

			String dropOrdersTable = "DROP TABLE IF EXISTS ORDERS";
			stmt.executeUpdate(dropOrdersTable);

			String dropUsersTable = "DROP TABLE IF EXISTS USERS";
			stmt.executeUpdate(dropUsersTable);

			String dropProductsTable = "DROP TABLE IF EXISTS PRODUCTS";
			stmt.executeUpdate(dropProductsTable);

			String createProductsTable = "CREATE TABLE PRODUCTS " +
					"(id INTEGER PRIMARY KEY, " +
					" name VARCHAR(255))";
			stmt.executeUpdate(createProductsTable);

			String createUsersTable = "CREATE TABLE USERS " +
					"(id INTEGER PRIMARY KEY, " + 
					" public_key VARCHAR(1024)) ";
			stmt.executeUpdate(createUsersTable);

			String createOrdersTable = "CREATE TABLE ORDERS " +
					"(id INTEGER PRIMARY KEY, " +
					" user_id INTEGER, " +
					" date TIMESTAMP DEFAULT (datetime('now','localtime')), " +
					" FOREIGN KEY (user_id) REFERENCES USERS(id)) ";
			stmt.executeUpdate(createOrdersTable);

			String createOrderDetailsTable = "CREATE TABLE ORDER_DETAILS " +
					" (order_id INTEGER, " +
					" product_id INTEGER, " +
					" quantity INTEGER, " +
					" FOREIGN KEY (order_id) REFERENCES ORDERS(id), " +
					" FOREIGN KEY (product_id) REFERENCES PRODUCTS(id)," +
					" PRIMARY KEY ( order_id, product_id)) " ;
			stmt.executeUpdate(createOrderDetailsTable);

			List<String> products = List.of("camas","mesas","sillas","sillones");
			for (String product : products) {
				stmt.addBatch("INSERT INTO PRODUCTS (name) VALUES ('"+product+"')");
			}
			stmt.executeBatch();

			String createUser = "INSERT INTO USERS (public_key) VALUES ('" + CLIENT_PUBLIC_KEY + "')";
			stmt.executeUpdate(createUser);
			
			System.out.println("Created tables in given database...");

			System.err.println("Waiting for connection...");
			ExecutorService threadPool = Executors.newFixedThreadPool(8);
			while (true) {
				try {
					final SSLSocket socket = (SSLSocket) serverSocket.accept();
					threadPool.execute(() -> {
						try {
							BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
							StringBuilder builder = new StringBuilder();
							String line;
							while ((line = input.readLine()) != null) {
								builder.append(line);
								builder.append(System.lineSeparator());
							}
							String json = builder.toString();
							PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
							
							System.out.println("Received: " + json);
							JSONObject jsonObject = null;
							try {
								jsonObject = new JSONObject(json);
							} catch (Exception e) {
								System.err.println("Error: " + e.getMessage());
								output.println("Petición INCORRECTA");
								output.flush();
								socket.close();
							}
							String clientId = jsonObject.getString("clientId");
							Signature sg = null;
							try {
								sg = Signature.getInstance("SHA256withRSA");
							} catch (Exception e) {
								System.err.println("Error: " + e.getMessage());
							}
							String signature = jsonObject.getString("signature");
							
							String messageJsonString = jsonObject.getString("message");
							JSONObject messageJson = new JSONObject(messageJsonString);
							Integer camas = Integer.valueOf(messageJson.getString("camas"));
							Integer mesas = Integer.valueOf(messageJson.getString("mesas"));
							Integer sillas = Integer.valueOf(messageJson.getString("sillas"));
							Integer sillones = Integer.valueOf(messageJson.getString("sillones"));

							Statement threadStatement = conn.createStatement();


							String strPublicKey = threadStatement.executeQuery("SELECT public_key FROM USERS WHERE id = " + clientId).getString("public_key");

							if (strPublicKey == null) {
								System.out.println("Client not found");
								output.println("Petición INCORRECTA");
								output.flush();
								socket.close();
								return;
							}

							PublicKey publicKey = null;
							try {
								publicKey = getPublicKeyFromString(strPublicKey);
							} catch (Exception e) {
								System.err.println("Error: " + e.getMessage());
							}
							try {
								sg.initVerify(publicKey);
							} catch (Exception e) {
								System.err.println("Error: " + e.getMessage());
							}
							
							try {
								sg.update(messageJsonString.getBytes());
							} catch (Exception e) {
								System.err.println("Error: " + e.getMessage());
							}

							Boolean isVerified = false;
							try {
								isVerified = sg.verify(getBytesFromString(signature));
							} catch (Exception e) {
								System.err.println("Error: " + e.getMessage());
							}
							if (!isVerified) {
								System.out.println("Signature is not valid");
								output.println("Petición INCORRECTA");
								output.flush();
								socket.close();
								return;
							}

							if (camas < 0 || mesas < 0 || sillas < 0 || sillones < 0) {
								System.out.println("Quantity of products is not valid");
								output.println("Petición INCORRECTA");
								output.flush();
								socket.close();
								return;
							}

							if (camas > 300 || mesas > 300 || sillas > 300 || sillones > 300) {
								System.out.println("Quantity of products is not valid");
								output.println("Petición INCORRECTA");
								output.flush();
								socket.close();
								return;
							}

							if (camas == 0 && mesas == 0 && sillas == 0 && sillones == 0) {
								System.out.println("Quantity of products is not valid");
								output.println("Petición INCORRECTA");
								output.flush();
								socket.close();
								return;
							}

							// Si el último pedido del cliente fue hace menos de 4 horas, rechazar el pedido
							String lastDateStr = threadStatement.executeQuery("SELECT date FROM ORDERS WHERE user_id = " + clientId + " ORDER BY date DESC LIMIT 1").getString("date");
							if (lastDateStr == null) {
								System.out.println("Client has no orders");
							} else {
								// 2024-05-09 11:29:18
								DateTimeFormatter formatter = new DateTimeFormatterBuilder().appendPattern("yyyy-MM-dd HH:mm:ss").toFormatter();
								LocalDateTime lastOrder = LocalDateTime.parse(lastDateStr, formatter);
								LocalDateTime now = LocalDateTime.now();
								if (lastOrder.plusHours(4).isAfter(now)) {
									System.out.println("Last order was less than 4 hours ago");
									output.println("Petición INCORRECTA");
									output.flush();
									socket.close();
									return;
								}
							}
							PreparedStatement orderStatement = conn.prepareStatement("INSERT INTO ORDERS (user_id) VALUES ("+clientId+")", Statement.RETURN_GENERATED_KEYS);
							orderStatement.executeUpdate();
							int orderId = -1;
							try (java.sql.ResultSet generatedKeys = orderStatement.getGeneratedKeys()) {
								if (generatedKeys.next()) {
									orderId = generatedKeys.getInt(1);
								}
							}

							if (orderId == -1) {
								System.out.println("Error creating order");
								output.println("Petición INCORRECTA");
								output.flush();
								socket.close();
								return;
							}

							if (camas > 0) {
								PreparedStatement orderDetailsStatement = conn.prepareStatement("INSERT INTO ORDER_DETAILS (order_id, product_id, quantity) VALUES ("+orderId+", 1, "+camas+")");
								orderDetailsStatement.executeUpdate();
							}

							if (mesas > 0) {
								PreparedStatement orderDetailsStatement = conn.prepareStatement("INSERT INTO ORDER_DETAILS (order_id, product_id, quantity) VALUES ("+orderId+", 2, "+mesas+")");
								orderDetailsStatement.executeUpdate();
							}

							if (sillas > 0) {
								PreparedStatement orderDetailsStatement = conn.prepareStatement("INSERT INTO ORDER_DETAILS (order_id, product_id, quantity) VALUES ("+orderId+", 3, "+sillas+")");
								orderDetailsStatement.executeUpdate();
							}

							if (sillones > 0) {
								PreparedStatement orderDetailsStatement = conn.prepareStatement("INSERT INTO ORDER_DETAILS (order_id, product_id, quantity) VALUES ("+orderId+", 4, "+sillones+")");
								orderDetailsStatement.executeUpdate();
							}

							output.println("Petición OK");
							output.flush();
							socket.close();

						} catch (IOException | SQLException e) {
							System.err.println("Error: " + e.getMessage());
						}
					});
				} catch (IOException e) {
					System.err.println("Error: " + e.getMessage());
				}
			}
		} catch (IOException e) {
			System.err.println("Error: " + e.getMessage());
		}
	}

	private static void loadEnvVariables() {
		try {
			File file = new File(System.getProperty("user.dir") + "\\server" + "\\" + ".properties");
			FileInputStream fis = new FileInputStream(file);
			BufferedReader br = new BufferedReader(new InputStreamReader(fis));
			String line;
			while ((line = br.readLine()) != null) {
				String[] parts = line.split("=", 2);
				if (parts.length == 2) {
					String key = parts[0].trim();
					String value = parts[1].trim();
					System.setProperty(key, value);
				}
			}
			br.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}

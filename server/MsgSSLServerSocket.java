package server;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.Signature;

import javax.net.ssl.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.json.JSONObject;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;

public class MsgSSLServerSocket {
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
			populateDb(conn, CLIENT_PUBLIC_KEY);

			System.err.println("Waiting for connection...");
			ExecutorService threadPool = Executors.newFixedThreadPool(8);
			ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

			scheduler.scheduleAtFixedRate(() -> {
				try {
					calculateOrderSuccessRate(conn, LocalDateTime.now().getMonthValue(), LocalDateTime.now().getYear());
					
				} catch (SQLException e) {
					System.err.println("Error calculating order success rate: " + e.getMessage());
				}
			}, 0, 30, TimeUnit.DAYS);

			while (true) {
				try {
					final SSLSocket socket = (SSLSocket) serverSocket.accept();
					threadPool.execute(() -> {
						try (BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
						PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()))) {

							String json = input.readLine();
							JSONObject jsonObject = null;
							try {
								jsonObject = new JSONObject(json);
							} catch (Exception e) {
								System.err.println("Error: " + e.getMessage());
								output.println("Petición INCORRECTA");
							}
							String clientId = jsonObject.getString("clientId");
							
							String signature = jsonObject.getString("signature");
							
							String messageJsonString = jsonObject.getString("message");
							JSONObject messageJson = new JSONObject(messageJsonString);
							Integer camas = Integer.valueOf(messageJson.getString("camas"));
							Integer mesas = Integer.valueOf(messageJson.getString("mesas"));
							Integer sillas = Integer.valueOf(messageJson.getString("sillas"));
							Integer sillones = Integer.valueOf(messageJson.getString("sillones"));

							Statement threadStatement = conn.createStatement();

							boolean verified = true;

							String strPublicKey = threadStatement.executeQuery("SELECT public_key FROM USERS WHERE id = '" + clientId +"'").getString("public_key");

							if (strPublicKey == null) {
								System.out.println("Client not found");
								verified = false;
								output.println("Petición INCORRECTA");
							} 
							if (verified && !verifySignature(strPublicKey, signature, messageJsonString)){
								System.out.println("Signature is not valid");
								verified = false;
								output.println("Petición INCORRECTA");
							}
							if (verified && (camas == 0 && mesas == 0 && sillas == 0 && sillones == 0) || 
								(camas < 0 || mesas < 0 || sillas < 0 || sillones < 0) || 
								(camas > 300 || mesas > 300 || sillas > 300 || sillones > 300)) {
								System.out.println("Quantity of products is not valid");
								verified = false;
								output.println("Petición INCORRECTA");
							}
							if (verified) {
								// Si el último pedido del cliente fue hace menos de 4 horas, rechazar el pedido
								String lastDateStr = threadStatement.executeQuery("SELECT date FROM ORDERS WHERE user_id = " + clientId + " ORDER BY date DESC LIMIT 1 OFFSET 2").getString("date");
								if (!(lastDateStr == null)) {
									// 2024-05-09 11:29:18
									DateTimeFormatter formatter = new DateTimeFormatterBuilder().appendPattern("yyyy-MM-dd HH:mm:ss").toFormatter();
									LocalDateTime lastOrder = LocalDateTime.parse(lastDateStr, formatter);
									LocalDateTime now = LocalDateTime.now();
									if (lastOrder.plusHours(4).isAfter(now)) {
										System.out.println("Last order was less than 4 hours ago");
										verified = false;
										output.println("Petición INCORRECTA");
									}else{
										output.println("Petición OK");
									}
								}else{
									output.println("Petición OK");
								}	
							}

							PreparedStatement preparedStatement = conn.prepareStatement("INSERT INTO ORDERS (user_id, camas, mesas, sillas, sillones, verificado) VALUES (?, ?, ?, ?, ?, ?)");
							preparedStatement.setString(1, clientId);
							preparedStatement.setInt(2, camas);
							preparedStatement.setInt(3, mesas); 
							preparedStatement.setInt(4, sillas);
							preparedStatement.setInt(5, sillones);
							preparedStatement.setBoolean(6, verified);
							preparedStatement.executeUpdate();
							System.out.println("Order created");

						} catch (IOException | SQLException e) {
							System.err.println("Error: " + e.getMessage());
						}finally {
							try {
								socket.close();
							} catch (IOException e) {
								System.err.println("Error: " + e.getMessage());
							}
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

	private static void populateDb(Connection conn, String CLIENT_PUBLIC_KEY) throws SQLException{

		System.out.println("Creating tables in given database...");
		Statement stmt = conn.createStatement();
		stmt.setQueryTimeout(30);

		
		stmt.addBatch("DROP TABLE IF EXISTS ORDERS");
		
		
		stmt.addBatch("DROP TABLE IF EXISTS USERS");


		stmt.addBatch("CREATE TABLE USERS " +
				"(id STRING PRIMARY KEY, " + 
				" public_key VARCHAR(1024)) ");

		stmt.addBatch("CREATE TABLE ORDERS " +
				"(id INTEGER PRIMARY KEY, " +
				" user_id STRING, " +
				" date TIMESTAMP DEFAULT (datetime('now','localtime')), " +
				" camas INTEGER, " +
				" mesas INTEGER, " +
				" sillas INTEGER, " +
				" sillones INTEGER, " +
				" verificado BOOLEAN, " +
				" FOREIGN KEY (user_id) REFERENCES USERS(id)) ");

		

		stmt.addBatch("INSERT INTO USERS (id, public_key) VALUES ('1','" + CLIENT_PUBLIC_KEY + "')");

		stmt.executeBatch();
		System.out.println("Created tables in given database...");
	

	}

	private static boolean verifySignature(String strPublicKey, String signature, String messageJsonString){
		Signature sg = null;
		try {
			sg = Signature.getInstance("SHA256withRSA");
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
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

		try {
			return sg.verify(getBytesFromString(signature));
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			return false;
		}
	}

	private static void calculateOrderSuccessRate(Connection conn, int month, int year) throws SQLException {
	    String totalOrdersQuery = "SELECT * FROM ORDERS WHERE strftime('%M', date) = ? AND strftime('%Y', date) = ?";
	
	    try (PreparedStatement totalOrdersStmt = conn.prepareStatement(totalOrdersQuery)) {
	
			totalOrdersStmt.setString(1, String.format("%02d", month));
			totalOrdersStmt.setString(2, String.valueOf(year));
			ResultSet totalOrdersResult = totalOrdersStmt.executeQuery();
			
			int totalOrdersSuccess = 0;
			int totalOrdersFailed = 0;

			while (totalOrdersResult.next()) {
				if(totalOrdersResult.getBoolean("verified")) {
					totalOrdersSuccess++;
				} else {
					totalOrdersFailed++;
				}
			}

			int totalOrders = totalOrdersSuccess + totalOrdersFailed;
			double successRate = 0.0;
			System.err.println("Total orders: " + totalOrders);
			if (totalOrders != 0) {
				System.err.println("Total orders: " + totalOrders);
				successRate = (double) totalOrdersSuccess / totalOrders;
			}

			try (PrintWriter out = new PrintWriter(new FileWriter("informe.txt", Charset.forName("UTF-8"), true))) {
				// Read the last two lines of the file
				List<String> lines = Files.readAllLines(Paths.get("informe.txt"));
				lines.removeIf(x->x.isBlank());
				int numLines = lines.size();
				Double lastSuccessRate = numLines > 0 ? Double.parseDouble(lines.get(numLines - 1).split(" ")[2]) : null;
				Double secondLastSuccessRate = numLines > 1 ? Double.parseDouble(lines.get(numLines - 2).split(" ")[2]) : null;
				//System.err.println(month + " " + year + " " + successRate + " ");
				// Determine the symbol to write
				String symbol;
				if (numLines < 2 || successRate == lastSuccessRate && successRate == secondLastSuccessRate) {
					symbol = "0";
				} else if (successRate > lastSuccessRate && successRate > secondLastSuccessRate) {
					symbol = "-";
				} else {
					symbol = "+";
				}
				out.println(month + " " + year + " " + successRate + " " + symbol);
			} catch (IOException e) {
				System.err.println("Error writing to file: " + e.getMessage());
			}
	    }
	}
}

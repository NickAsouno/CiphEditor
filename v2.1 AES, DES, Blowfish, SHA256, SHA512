import java.awt.Color;
import java.awt.FileDialog;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.geom.Rectangle2D;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.undo.UndoManager;

public class AES_Blowfish_DES {
	static String fontname = "Arial";
	static int fontsize = 12;
    static Font mainfont = new Font(fontname, Font.PLAIN, fontsize);
	public static void main(String[] args) {

		JFrame frcp = new JFrame();
		frcp.setSize(264, 25);
		frcp.setBounds(828, 10, 264, 25);
		frcp.setUndecorated(true);
		frcp.setShape(new Rectangle2D.Double(0, 0, 264, 25));
		frcp.setAlwaysOnTop(true);
		
		JMenuBar mb = new JMenuBar();
		JMenu mf = new JMenu("File");
		JMenu me = new JMenu("Edit");
		JMenu mt = new JMenu("Theme");
		JMenu mfo = new JMenu("Font");
		JMenu mfs = new JMenu("Font Size");
		
		JMenu meab = new JMenu("Blowfish + AES + DES");
		JMenu mea = new JMenu("AES");
		JMenu med = new JMenu("DES");
		JMenu meb = new JMenu("Blowfish");
		JMenu mes256 = new JMenu("SHA-256");
		JMenu mes512 = new JMenu("SHA-512");
		
		JMenuItem meabe = new JMenuItem("Encrypt");
		JMenuItem meabd = new JMenuItem("Decrypt");
		
		JMenuItem meae = new JMenuItem("Encrypt");
		JMenuItem mead = new JMenuItem("Decrypt");
		
		JMenuItem mebe = new JMenuItem("Encrypt");
		JMenuItem mebd = new JMenuItem("Decrypt");
		
		JMenuItem mede = new JMenuItem("Encrypt");
		JMenuItem medd = new JMenuItem("Decrypt");
		
		JMenuItem mes256e = new JMenuItem("Encrypt");
		
		JMenuItem mes512e = new JMenuItem("Encrypt");
		
		JMenuItem mitb = new JMenuItem("Black");
		JMenuItem mitw = new JMenuItem("White");
		JMenuItem miesa = new JMenuItem("Select All");
		JMenuItem mieu = new JMenuItem("Undo");
		JMenuItem mier = new JMenuItem("Redo");
		JTextField tpfn = new JTextField("Arial");
		JButton apllyfont = new JButton("Apply");
		apllyfont.setFocusable(false);
		apllyfont.setBackground(Color.white);
		
		JButton mifsp = new JButton("+");
		mifsp.setFocusable(false);
		mifsp.setBackground(Color.white);
		mifsp.setFont(new Font("Arial", Font.PLAIN, 20));
		JButton mifsm = new JButton("-");
		mifsm.setFocusable(false);
		mifsm.setBackground(Color.white);
		mifsm.setFont(new Font("Arial", Font.PLAIN, 20));
		
		JTextField tpfs = new JTextField(String.valueOf(fontsize)); 
		tpfs.setEditable(false);
		
		mf.add(meab);
		mf.add(mea);
		mf.add(meb);
		mf.add(med);
		mf.add(mes256);
		mf.add(mes512);
		
		med.add(mifsm);
		
		mfs.add(mifsm);
		mfs.add(mifsp);
		
		meab.add(meabe);
		meab.add(meabd);
		
		mea.add(meae);
		mea.add(mead);
		
		meb.add(mebe);
		meb.add(mebd);
		
		med.add(mede);
		med.add(medd);
		
		mes256.add(mes256e);
		
		mes512.add(mes512e);
		
		mt.add(mitb);
		mt.add(mitw);
		
		mfo.add(tpfn);
		mfo.add(apllyfont);
		
		me.add(mieu);
		me.add(mier);
		me.add(miesa);
		
		mb.add(mf);
		mb.add(me);
		mb.add(mt);
		mb.add(mfo);
		mb.add(mfs);
		mb.add(tpfs);
		
		frcp.add(mb);
		
		frcp.setVisible(true);
		
		JFrame fr = new JFrame();
		fr.setSize(800, 500);
		fr.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JTextArea tp = new JTextArea();
        tp.setSize(800, 500);
        
        UndoManager manager = new UndoManager();
        tp.getDocument().addUndoableEditListener(manager);
        
        JScrollPane sc = new JScrollPane(tp);
        sc.setSize(800, 500);
        fr.add(sc);
        
        ActionListener eab = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				    save_file_AES_Blowfish_DES(tp.getText());
		        }
		};
		meabe.addActionListener(eab);
		
		ActionListener dab = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				     tp.setText(de_AES_Blowfish_DES());
		        }
		};
		meabd.addActionListener(dab);
		
		 ActionListener ea = new ActionListener() {
				public void actionPerformed(ActionEvent ae) {
					    save_file_AES(tp.getText());
			        }
		};
		meae.addActionListener(ea);
			
		ActionListener da = new ActionListener() {
				public void actionPerformed(ActionEvent ae) {
					     tp.setText(de_AES());
			        }
		};
		mead.addActionListener(da);
		
		ActionListener eb = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				    save_file_Blowfish(tp.getText());
		        }
	    };
	    mebe.addActionListener(eb);
		
	    ActionListener db = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				     tp.setText(de_Blowfish());
		        }
	    };
	    mebd.addActionListener(db);
	    
	    ActionListener ed = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				    save_file_DES(tp.getText());
		        }
	    };
	    mede.addActionListener(ed);
		
	    ActionListener dd = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				     tp.setText(de_DES());
		        }
	    };
	    medd.addActionListener(dd);
		
		ActionListener es256 = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				save_file_SHA256(tp.getText());
		        }
		};
		mes256e.addActionListener(es256);
		
		ActionListener es512 = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				     save_file_SHA512(tp.getText());
		        }
		};
		mes512e.addActionListener(es512);
		
		ActionListener tb = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				    tp.setLineWrap(true);
				    tp.setBackground(Color.black);
				    tp.setForeground(Color.white);
				    sc.setBackground(Color.black);
				    sc.setForeground(Color.white);
				    
		        }
		};
		mitb.addActionListener(tb);
		
		ActionListener tw = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				    tp.setLineWrap(true);
				    tp.setBackground(Color.white);
				    tp.setForeground(Color.black);
				    sc.setBackground(Color.white);
				    sc.setForeground(Color.black);
				    
		        }
		};
		mitw.addActionListener(tw);
		
		ActionListener fsp = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				    fontsize += 1;
				    mainfont = new Font(fontname, Font.PLAIN, fontsize);
				    tp.setFont(mainfont);
				    sc.setFont(mainfont);
				    tpfs.setText(String.valueOf(fontsize));
				    fr.repaint();
		        }
		};
		mifsp.addActionListener(fsp);
		
		ActionListener fsm = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				    fontsize-=1;
				    mainfont = new Font(fontname, Font.PLAIN, fontsize);
				    tp.setFont(mainfont);
				    sc.setFont(mainfont);
				    tpfs.setText(String.valueOf(fontsize));
				    fr.repaint();
		        }
		};
		mifsm.addActionListener(fsm);
		
		ActionListener aplfnt = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				    fontname=tpfn.getText();
				    mainfont = new Font(fontname, Font.PLAIN, fontsize);
				    tp.setFont(mainfont);
				    sc.setFont(mainfont);
				    fr.repaint();
		        }
		};
		apllyfont.addActionListener(aplfnt);
		
		ActionListener sela = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				    tp.selectAll();
		        }
		};
		miesa.addActionListener(sela);
		
		ActionListener undo = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				   manager.undo();
		        }
		};
		mieu.addActionListener(undo);
		
		ActionListener redo = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				   manager.redo();
		        }
		};
		mier.addActionListener(redo);
        
        fr.setVisible(true);
	}
	static String encrypt_DES(String input, String key) {
		String result = "";
		
		try {
			SecretKeySpec myDesKey = new SecretKeySpec(key.getBytes(),"DES");
	        Cipher myCipher = Cipher.getInstance("DES");
	        myCipher.init(Cipher.ENCRYPT_MODE, myDesKey);
	        byte[] myEncryptedBytes=myCipher.doFinal(input.getBytes());
	        
	        result = Base64.getEncoder().encodeToString(myEncryptedBytes);
		}
		catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
		    e.printStackTrace();  
		}
		return result;
	}
	
	static String decrypt_DES(String input, String key) {
		String result = "";
		byte[] decode = Base64.getDecoder().decode(input);
		try {
	        SecretKeySpec myDesKey = new SecretKeySpec(key.getBytes(), "DES");
			Cipher cp = Cipher.getInstance("DES");
	        cp.init(Cipher.DECRYPT_MODE, myDesKey);
	        byte[] myDecryptedBytes = cp.doFinal(decode);
	        
	        result = new String(myDecryptedBytes);
		}
		catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
		    e.printStackTrace();  
		}
		return result;
	}
	
	static String pBin(String binary, int blockSize, String separator) {
	    List<String> result = new ArrayList<>();
	    int index = 0;
	    while (index < binary.length()) {
	        result.add(binary.substring(index, Math.min(index + blockSize, binary.length())));
	        index += blockSize;
	    }
	    return result.stream().collect(Collectors.joining(separator));
	}
	
	static String to_str(String input) {
		String[] parts = pBin(input, 8, " ").split(" ");
		String sb = "";

		for (String part : parts) {
		    int val = Integer.parseInt(part, 2);
		    String c = Character.toString(val);
		    sb+=(c);
		}
		return sb;
	}
	
	static void save_file_AES_Blowfish_DES(String input) {
		String keyofaes = randomkey(input.length()*2);
		String keyofblowfish = randomkey(56);
		String keyofdes = randomkey(8);
		
		JFrame f = new JFrame();
		FileDialog fd = new FileDialog(f, "Save a key", FileDialog.SAVE);
		fd.setVisible(true);
		try {
			  File fil = new File(fd.getDirectory()+fd.getFile()); 
		      FileWriter myWriter = new FileWriter(fil);
		      myWriter.write(keyofaes+"=+{keySEP}+="+keyofdes+"=+{keySEP}+="+keyofblowfish);
		      myWriter.close();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		String Blowfished = encryptBlowfish(input, keyofblowfish);
		String DESed = encrypt_DES(Blowfished, keyofdes);
		String AESed = encryptAES(DESed, keyofaes);
		
		JFrame f2 = new JFrame();
		FileDialog fd2 = new FileDialog(f2, "Save a ciphertext", FileDialog.SAVE);
		fd2.setVisible(true);
		try {
			  File fil = new File(fd2.getDirectory()+fd2.getFile()); 
		      FileWriter myWriter = new FileWriter(fil);
		      myWriter.write(AESed);
		      myWriter.close();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
    }
	
	static void save_file_AES(String input) {
		String keyofaes = randomkey(input.length());
		
		JFrame f = new JFrame();
		FileDialog fd = new FileDialog(f, "Save a key", FileDialog.SAVE);
		fd.setVisible(true);
		try {
			  File fil = new File(fd.getDirectory()+fd.getFile()); 
		      FileWriter myWriter = new FileWriter(fil);
		      myWriter.write(keyofaes);
		      myWriter.close();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		String AESed = encryptAES(input, keyofaes);
		JFrame f2 = new JFrame();
		FileDialog fd2 = new FileDialog(f2, "Save a ciphertext", FileDialog.SAVE);
		fd2.setVisible(true);
		try {
			  File fil = new File(fd2.getDirectory()+fd2.getFile()); 
		      FileWriter myWriter = new FileWriter(fil);
		      myWriter.write(AESed);
		      myWriter.close();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
    }
	
	static void save_file_Blowfish(String input) {
		String keyofblowfish = randomkey(56);
		
		JFrame f = new JFrame();
		FileDialog fd = new FileDialog(f, "Save a key", FileDialog.SAVE);
		fd.setVisible(true);
		try {
			  File fil = new File(fd.getDirectory()+fd.getFile()); 
		      FileWriter myWriter = new FileWriter(fil);
		      myWriter.write(keyofblowfish);
		      myWriter.close();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		String Blowfished = encryptBlowfish(input, keyofblowfish);
		JFrame f2 = new JFrame();
		FileDialog fd2 = new FileDialog(f2, "Save a ciphertext", FileDialog.SAVE);
		fd2.setVisible(true);
		try {
			  File fil = new File(fd2.getDirectory()+fd2.getFile()); 
		      FileWriter myWriter = new FileWriter(fil);
		      myWriter.write(Blowfished);
		      myWriter.close();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
    }
	
	static void save_file_DES(String input) {
		String keyofDES = randomkey(8);
		
		JFrame f = new JFrame();
		FileDialog fd = new FileDialog(f, "Save a key", FileDialog.SAVE);
		fd.setVisible(true);
		try {
			  File fil = new File(fd.getDirectory()+fd.getFile()); 
		      FileWriter myWriter = new FileWriter(fil);
		      myWriter.write(keyofDES);
		      myWriter.close();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		String DESed = encrypt_DES(input, keyofDES);
		JFrame f2 = new JFrame();
		FileDialog fd2 = new FileDialog(f2, "Save a ciphertext", FileDialog.SAVE);
		fd2.setVisible(true);
		try {
			  File fil = new File(fd2.getDirectory()+fd2.getFile()); 
		      FileWriter myWriter = new FileWriter(fil);
		      myWriter.write(DESed);
		      myWriter.close();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
    }
	
	static String de_DES() {
		String result = "";
		String key = "";
		
		JFrame f = new JFrame();
		FileDialog fd = new FileDialog(f, "Select key", FileDialog.LOAD);
		fd.setVisible(true);
		
		char[] ch = new char[10000000];
		try {
			  File fil = new File(fd.getDirectory()+fd.getFile()); 
		      FileReader reader = new FileReader(fil);
		      reader.read(ch);
		      reader.close();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		
		key = String.valueOf(ch).replace(to_str("00000000"), "");
		
		JFrame f2 = new JFrame();
		FileDialog fd2 = new FileDialog(f2, "Select Ciphertext", FileDialog.LOAD);
		fd2.setVisible(true);
		char[] ch2 = new char[10000000];
		try {
			  File fil = new File(fd2.getDirectory()+fd2.getFile()); 
		      FileReader reader = new FileReader(fil);
		      reader.read(ch2);
		      reader.close();
			}
		catch (IOException e) {
				e.printStackTrace();
		}
		result = String.valueOf(ch2).replace(to_str("00000000"), "");
		
		String unDESed = decrypt_DES(result, key);
		
		return unDESed;
	}
	
	static void save_file_SHA256(String input) {
		String SHAed = sha256(input);
		JFrame f2 = new JFrame();
		FileDialog fd2 = new FileDialog(f2, "Save a ciphertext", FileDialog.SAVE);
		fd2.setVisible(true);
		try {
			  File fil = new File(fd2.getDirectory()+fd2.getFile()); 
		      FileWriter myWriter = new FileWriter(fil);
		      myWriter.write(SHAed);
		      myWriter.close();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
    }
	
	static void save_file_SHA512(String input) {
		String SHAed = sha512(input);
		JFrame f2 = new JFrame();
		FileDialog fd2 = new FileDialog(f2, "Save a ciphertext", FileDialog.SAVE);
		fd2.setVisible(true);
		try {
			  File fil = new File(fd2.getDirectory()+fd2.getFile()); 
		      FileWriter myWriter = new FileWriter(fil);
		      myWriter.write(SHAed);
		      myWriter.close();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
    }
	
	static String de_AES_Blowfish_DES() {
		String result = "";
		String key = "";
		
		JFrame f = new JFrame();
		FileDialog fd = new FileDialog(f, "Select key", FileDialog.LOAD);
		fd.setVisible(true);
		
		char[] ch = new char[10000000];
		try {
			  File fil = new File(fd.getDirectory()+fd.getFile()); 
		      FileReader reader = new FileReader(fil);
		      reader.read(ch);
		      reader.close();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		
		key = String.valueOf(ch).replace(to_str("00000000"), "");
		
		JFrame f2 = new JFrame();
		FileDialog fd2 = new FileDialog(f2, "Select Ciphertext", FileDialog.LOAD);
		fd2.setVisible(true);
		char[] ch2 = new char[10000000];
		try {
			  File fil = new File(fd2.getDirectory()+fd2.getFile()); 
		      FileReader reader = new FileReader(fil);
		      reader.read(ch2);
		      reader.close();
			}
		catch (IOException e) {
				e.printStackTrace();
		}
		result = String.valueOf(ch2).replace(to_str("00000000"), "");
		
		String[] splitKey = key.replace("=+{keySEP}+=", "SEPARATOR.KEY").split("SEPARATOR.KEY", 99999999);
		
		String unAESed = decryptAES(result, splitKey[0]);
		String unDESed = decrypt_DES(unAESed, splitKey[1]);
		String unBlowfished = decryptBlowfish(unDESed, splitKey[2]);
		
		return unBlowfished;
	}
	
	static String de_AES() {
		String result = "";
		String key = "";
		
		JFrame f = new JFrame();
		FileDialog fd = new FileDialog(f, "Select key", FileDialog.LOAD);
		fd.setVisible(true);
		
		char[] ch = new char[10000000];
		try {
			  File fil = new File(fd.getDirectory()+fd.getFile()); 
		      FileReader reader = new FileReader(fil);
		      reader.read(ch);
		      reader.close();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		
		key = String.valueOf(ch).replace(to_str("00000000"), "");
		
		JFrame f2 = new JFrame();
		FileDialog fd2 = new FileDialog(f2, "Select Ciphertext", FileDialog.LOAD);
		fd2.setVisible(true);
		char[] ch2 = new char[10000000];
		try {
			  File fil = new File(fd2.getDirectory()+fd2.getFile()); 
		      FileReader reader = new FileReader(fil);
		      reader.read(ch2);
		      reader.close();
			}
		catch (IOException e) {
				e.printStackTrace();
		}
		result = String.valueOf(ch2).replace(to_str("00000000"), "");
		
		String unAESed = decryptAES(result, key);
		
		return unAESed;
	}
	
	static String de_Blowfish() {
		String result = "";
		String key = "";
		
		JFrame f = new JFrame();
		FileDialog fd = new FileDialog(f, "Select key", FileDialog.LOAD);
		fd.setVisible(true);
		
		char[] ch = new char[10000000];
		try {
			  File fil = new File(fd.getDirectory()+fd.getFile()); 
		      FileReader reader = new FileReader(fil);
		      reader.read(ch);
		      reader.close();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		
		key = String.valueOf(ch).replace(to_str("00000000"), "");
		
		JFrame f2 = new JFrame();
		FileDialog fd2 = new FileDialog(f2, "Select Ciphertext", FileDialog.LOAD);
		fd2.setVisible(true);
		char[] ch2 = new char[10000000];
		try {
			  File fil = new File(fd2.getDirectory()+fd2.getFile()); 
		      FileReader reader = new FileReader(fil);
		      reader.read(ch2);
		      reader.close();
			}
		catch (IOException e) {
				e.printStackTrace();
		}
		result = String.valueOf(ch2).replace(to_str("00000000"), "");
		
		String unBlowfisheded = decryptBlowfish(result, key);
		
		return unBlowfisheded;
	}
	
	static String randomkey(int len){
    	String AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder(len);
        for(int i = 0; i < len; i++)
           sb.append(AB.charAt(rnd.nextInt(AB.length())));
        return sb.toString();
    } 
   
    public static String encryptAES(String strToEncrypt, String SECRET_KEY) {  
    try {  
      
      byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};  
      IvParameterSpec ivspec = new IvParameterSpec(iv);        
      
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");  
    
      KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), "this is salt value".getBytes(), 65536, 256);  
      SecretKey tmp = factory.generateSecret(spec);  
      SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");  
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");  
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);  
     
      return Base64.getEncoder()  
.encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));  
    }   
    catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e)   
    {  
      System.out.println("Error occured during encryption: " + e.toString());  
    }  
    return null;  
    }  
    
    public static String decryptAES(String strToDecrypt, String SECRET_KEY) {  
        try {  
          
          byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};  
          IvParameterSpec ivspec = new IvParameterSpec(iv);  
         
          SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");  
          
          KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), "this is salt value".getBytes(), 65536, 256);  
          SecretKey tmp = factory.generateSecret(spec);  
          SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");  
          Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");  
          cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);  
         
          return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));  
        }   
        catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e)   
        {  
          System.out.println("Error occured during decryption: " + e.toString());  
        }  
        return null;  
        }
    
    static String encryptBlowfish(String input, String key) {
    	String result = "";
    	
    	try {
    		byte[] KeyData = key.getBytes();
            SecretKeySpec KS = new SecretKeySpec(KeyData, "Blowfish");
            Cipher cipher = Cipher.getInstance("Blowfish");
            cipher.init(Cipher.ENCRYPT_MODE, KS);
            result = Base64.getEncoder().encodeToString(cipher.doFinal(input.getBytes()));
          }   
          catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e)   
          {  
            System.out.println("Error occured during decryption: " + e.toString());  
          }
    	
    	return result;
    }
    
    static String decryptBlowfish(String input, String key) {
    	String result = "";
    	
    	try {
    		byte[] KeyData = key.getBytes();
            SecretKeySpec KS = new SecretKeySpec(KeyData, "Blowfish");
            byte[] ecryptedtexttobytes = Base64.getDecoder().decode(input);
            Cipher cipher = Cipher.getInstance("Blowfish");
            cipher.init(Cipher.DECRYPT_MODE, KS);
            byte[] decrypted = cipher.doFinal(ecryptedtexttobytes);
            result = new String(decrypted, Charset.forName("UTF-8"));
          }   
          catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e)   
          {  
            System.out.println("Error occured during decryption: " + e.toString());  
          }
    	
    	return result;
    }
    
    
    
    public static String sha256(final String base) {
        try{
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] hash = digest.digest(base.getBytes("UTF-8"));
            final StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < hash.length; i++) {
                final String hex = Integer.toHexString(0xff & hash[i]);
                if(hex.length() == 1) 
                  hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch(Exception ex){
           throw new RuntimeException(ex);
        }
    }
    
    public static String sha512(final String base) {
        try{
            final MessageDigest digest = MessageDigest.getInstance("SHA-512");
            final byte[] hash = digest.digest(base.getBytes("UTF-8"));
            final StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < hash.length; i++) {
                final String hex = Integer.toHexString(0xff & hash[i]);
                if(hex.length() == 1) 
                  hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch(Exception ex){
           throw new RuntimeException(ex);
        }
    }

}

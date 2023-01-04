import java.nio.charset.StandardCharsets;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.geom.*;
import javax.swing.undo.*;
public class MainClass {
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
		JMenuItem mis = new JMenuItem("Encrypt");
		JMenuItem mid = new JMenuItem("Decrypt");
		JMenuItem mitb = new JMenuItem("Black");
		JMenuItem mitw = new JMenuItem("While");
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
		
		mfs.add(mifsm);
		mfs.add(mifsp);
		
		mf.add(mis);
		mf.add(mid);
		
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
        
        ActionListener sf = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				    save_file(tp.getText());
		        }
		};
		mis.addActionListener(sf);
		
		ActionListener scp = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				    tp.setText(selectCiphertext());
		        }
		};
		mid.addActionListener(scp);
		
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
	
	static void save_file(String input) {
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
	
	static String selectKey() {
		String result = "";
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
		
		result = String.valueOf(ch).replace(to_str("00000000"), "");
		
		return result;
	}
	
	static String selectCiphertext() {
		String result = "";
		
		String key = selectKey();
		
		JFrame f = new JFrame();
		FileDialog fd = new FileDialog(f, "Select Ciphertext", FileDialog.LOAD);
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
		result = String.valueOf(ch).replace(to_str("00000000"), "");
		
		String unAESed = decryptAES(result, key);
		
		return unAESed;
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
    
}

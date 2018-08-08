/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.company;

import java.awt.Color;
import java.io.File;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 *
 * @author Abdulsalam Mansour
 */
public class MainFrame extends javax.swing.JFrame {

    /**
     * Creates new form MainFrame
     */
    public MainFrame() {
        initComponents();
        jFileChooser1.setControlButtonsAreShown(false);
        jFileChooser2.setControlButtonsAreShown(false);
        jFileChooser3.setControlButtonsAreShown(false);
        jFileChooser1.setFileSelectionMode(jFileChooser1.FILES_AND_DIRECTORIES);
        jFileChooser2.setFileSelectionMode(jFileChooser2.FILES_AND_DIRECTORIES);
        jFileChooser3.setFileSelectionMode(jFileChooser3.FILES_AND_DIRECTORIES);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        jPanel2 = new javax.swing.JPanel();
        btnEncrypt = new javax.swing.JButton();
        btnDecrypt = new javax.swing.JButton();
        btnRecover = new javax.swing.JButton();
        jPanel3 = new javax.swing.JPanel();
        jPanel4 = new javax.swing.JPanel();
        jTextField1 = new javax.swing.JTextField();
        jButton1 = new javax.swing.JButton();
        jFileChooser1 = new javax.swing.JFileChooser();
        jLabel1 = new javax.swing.JLabel();
        jComboBox1 = new javax.swing.JComboBox<>();
        jLabel4 = new javax.swing.JLabel();
        jPanel5 = new javax.swing.JPanel();
        encryptSelection = new javax.swing.JComboBox<>();
        jButton2 = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        jFileChooser2 = new javax.swing.JFileChooser();
        txtEncryptKey = new javax.swing.JTextField();
        jLabel3 = new javax.swing.JLabel();
        jPanel6 = new javax.swing.JPanel();
        jFileChooser3 = new javax.swing.JFileChooser();
        jLabel5 = new javax.swing.JLabel();
        JtextKey = new javax.swing.JTextField();
        txtRecover = new javax.swing.JTextField();
        jLabel6 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        jButton3 = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jPanel1.setBackground(new java.awt.Color(0, 0, 51));

        jPanel2.setBackground(new java.awt.Color(0, 0, 51));
        jPanel2.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED, java.awt.Color.white, java.awt.Color.white, java.awt.Color.white, java.awt.Color.white));
        jPanel2.setLayout(new java.awt.BorderLayout());

        btnEncrypt.setBackground(new java.awt.Color(0, 0, 51));
        btnEncrypt.setForeground(new java.awt.Color(255, 255, 255));
        btnEncrypt.setText("Encrypt");
        btnEncrypt.setMaximumSize(new java.awt.Dimension(100, 100));
        btnEncrypt.setMinimumSize(new java.awt.Dimension(100, 100));
        btnEncrypt.setPreferredSize(new java.awt.Dimension(100, 100));
        btnEncrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnEncryptActionPerformed(evt);
            }
        });
        jPanel2.add(btnEncrypt, java.awt.BorderLayout.CENTER);

        btnDecrypt.setBackground(new java.awt.Color(0, 0, 51));
        btnDecrypt.setForeground(new java.awt.Color(255, 255, 255));
        btnDecrypt.setText("Decrypt");
        btnDecrypt.setMaximumSize(new java.awt.Dimension(100, 100));
        btnDecrypt.setMinimumSize(new java.awt.Dimension(100, 100));
        btnDecrypt.setPreferredSize(new java.awt.Dimension(100, 100));
        btnDecrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDecryptActionPerformed(evt);
            }
        });
        jPanel2.add(btnDecrypt, java.awt.BorderLayout.PAGE_START);

        btnRecover.setBackground(new java.awt.Color(0, 0, 51));
        btnRecover.setForeground(new java.awt.Color(255, 255, 255));
        btnRecover.setText("Recover");
        btnRecover.setMaximumSize(new java.awt.Dimension(100, 100));
        btnRecover.setMinimumSize(new java.awt.Dimension(100, 100));
        btnRecover.setPreferredSize(new java.awt.Dimension(100, 100));
        btnRecover.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRecoverActionPerformed(evt);
            }
        });
        jPanel2.add(btnRecover, java.awt.BorderLayout.PAGE_END);

        jPanel3.setBackground(new java.awt.Color(0, 0, 51));
        jPanel3.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED, java.awt.Color.white, java.awt.Color.white, java.awt.Color.white, java.awt.Color.white));
        jPanel3.setLayout(new java.awt.CardLayout());

        jPanel4.setBackground(new java.awt.Color(0, 0, 51));
        jPanel4.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED, java.awt.Color.white, java.awt.Color.white, java.awt.Color.white, java.awt.Color.white));
        jPanel4.setPreferredSize(new java.awt.Dimension(700, 700));

        jButton1.setText("Decrypt");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jLabel1.setBackground(new java.awt.Color(0, 0, 51));
        jLabel1.setForeground(new java.awt.Color(255, 255, 255));
        jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel1.setText("Key");

        jComboBox1.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Caesar Cipher", "Vigenere Cipher", "Vector Of Permutations Cipher", "Manhattan Cipher" }));
        jComboBox1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jComboBox1ActionPerformed(evt);
            }
        });

        jLabel4.setBackground(new java.awt.Color(0, 0, 51));
        jLabel4.setFont(new java.awt.Font("Times New Roman", 1, 24)); // NOI18N
        jLabel4.setForeground(new java.awt.Color(255, 255, 255));
        jLabel4.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel4.setText("Decrypt File");

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
                jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(jPanel4Layout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 38, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                        .addComponent(jLabel4, javax.swing.GroupLayout.DEFAULT_SIZE, 534, Short.MAX_VALUE)
                                        .addComponent(jTextField1)
                                        .addComponent(jFileChooser1, javax.swing.GroupLayout.DEFAULT_SIZE, 534, Short.MAX_VALUE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                        .addComponent(jComboBox1, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(jButton1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel4Layout.setVerticalGroup(
                jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(jPanel4Layout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(jPanel4Layout.createSequentialGroup()
                                                .addGap(0, 532, Short.MAX_VALUE)
                                                .addComponent(jComboBox1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addComponent(jFileChooser1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addGap(18, 18, 18)
                                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, 38, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 38, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jLabel1))
                                .addGap(46, 46, 46))
        );

        jPanel3.add(jPanel4, "card2");

        jPanel5.setBackground(new java.awt.Color(0, 0, 51));
        jPanel5.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED, java.awt.Color.white, java.awt.Color.white, java.awt.Color.white, java.awt.Color.white));
        jPanel5.setPreferredSize(new java.awt.Dimension(689, 544));

        encryptSelection.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Caesar Cipher", "Vigenere Cipher", "Vector Of Permutations Cipher", "Manhattan Cipher" }));

        jButton2.setText("Encrypt");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        jLabel2.setBackground(new java.awt.Color(0, 0, 51));
        jLabel2.setForeground(new java.awt.Color(255, 255, 255));
        jLabel2.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel2.setText("Key");

        jLabel3.setBackground(new java.awt.Color(0, 0, 51));
        jLabel3.setFont(new java.awt.Font("Times New Roman", 1, 24)); // NOI18N
        jLabel3.setForeground(new java.awt.Color(255, 255, 255));
        jLabel3.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel3.setText("Encrypt File");

        javax.swing.GroupLayout jPanel5Layout = new javax.swing.GroupLayout(jPanel5);
        jPanel5.setLayout(jPanel5Layout);
        jPanel5Layout.setHorizontalGroup(
                jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(jPanel5Layout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 38, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                        .addComponent(jLabel3, javax.swing.GroupLayout.DEFAULT_SIZE, 534, Short.MAX_VALUE)
                                        .addComponent(txtEncryptKey)
                                        .addComponent(jFileChooser2, javax.swing.GroupLayout.DEFAULT_SIZE, 534, Short.MAX_VALUE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                        .addComponent(encryptSelection, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(jButton2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addContainerGap(280, Short.MAX_VALUE))
        );
        jPanel5Layout.setVerticalGroup(
                jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(jPanel5Layout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(jPanel5Layout.createSequentialGroup()
                                                .addGap(0, 0, Short.MAX_VALUE)
                                                .addComponent(encryptSelection, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addComponent(jFileChooser2, javax.swing.GroupLayout.DEFAULT_SIZE, 545, Short.MAX_VALUE))
                                .addGap(18, 18, 18)
                                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(txtEncryptKey, javax.swing.GroupLayout.PREFERRED_SIZE, 38, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jButton2, javax.swing.GroupLayout.PREFERRED_SIZE, 38, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jLabel2))
                                .addGap(46, 46, 46))
        );

        jPanel3.add(jPanel5, "card2");

        jPanel6.setBackground(new java.awt.Color(0, 0, 51));
        jPanel6.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED, java.awt.Color.white, java.awt.Color.white, java.awt.Color.white, java.awt.Color.white));
        jPanel6.setPreferredSize(new java.awt.Dimension(689, 544));

        jLabel5.setBackground(new java.awt.Color(0, 0, 51));
        jLabel5.setFont(new java.awt.Font("Times New Roman", 1, 24)); // NOI18N
        jLabel5.setForeground(new java.awt.Color(255, 255, 255));
        jLabel5.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel5.setText("Recover File");

        jLabel6.setBackground(new java.awt.Color(0, 0, 51));
        jLabel6.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel6.setForeground(new java.awt.Color(255, 255, 255));
        jLabel6.setText("Admin Key");

        jLabel7.setBackground(new java.awt.Color(0, 0, 51));
        jLabel7.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel7.setForeground(new java.awt.Color(255, 255, 255));
        jLabel7.setText("Recovered Key");

        jButton3.setText("Recover");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel6Layout = new javax.swing.GroupLayout(jPanel6);
        jPanel6.setLayout(jPanel6Layout);
        jPanel6Layout.setHorizontalGroup(
                jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(jPanel6Layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(jLabel5, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(jFileChooser3, javax.swing.GroupLayout.DEFAULT_SIZE, 926, Short.MAX_VALUE)
                                        .addGroup(jPanel6Layout.createSequentialGroup()
                                                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                                        .addComponent(jLabel7, javax.swing.GroupLayout.DEFAULT_SIZE, 97, Short.MAX_VALUE)
                                                        .addComponent(jLabel6, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                                        .addComponent(JtextKey, javax.swing.GroupLayout.DEFAULT_SIZE, 642, Short.MAX_VALUE)
                                                        .addComponent(txtRecover))
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                .addComponent(jButton3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                .addGap(2, 2, 2)))
                                .addContainerGap())
        );
        jPanel6Layout.setVerticalGroup(
                jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(jPanel6Layout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(jLabel5, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jFileChooser3, javax.swing.GroupLayout.PREFERRED_SIZE, 455, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(43, 43, 43)
                                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(JtextKey, javax.swing.GroupLayout.PREFERRED_SIZE, 32, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jLabel6, javax.swing.GroupLayout.PREFERRED_SIZE, 32, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(txtRecover, javax.swing.GroupLayout.PREFERRED_SIZE, 32, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jLabel7, javax.swing.GroupLayout.PREFERRED_SIZE, 32, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jButton3, javax.swing.GroupLayout.PREFERRED_SIZE, 33, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addContainerGap(69, Short.MAX_VALUE))
        );

        jPanel3.add(jPanel6, "card2");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
                jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(jPanel1Layout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jPanel3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
                jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(jPanel1Layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(jPanel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(jPanel3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addContainerGap())
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void btnDecryptActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDecryptActionPerformed
        // TODO add your handling code here:

        //removing panel
        jPanel3.removeAll();
        jPanel3.repaint();
        jPanel3.revalidate();

        //adding panel
        jPanel3.add(jPanel4);
        jPanel3.repaint();
        jPanel3.revalidate();

    }//GEN-LAST:event_btnDecryptActionPerformed

    private void btnEncryptActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnEncryptActionPerformed
        // TODO add your handling code here:

        //removing panel
        jPanel3.removeAll();
        jPanel3.repaint();
        jPanel3.revalidate();

        //adding panel
        jPanel3.add(jPanel5);
        jPanel3.repaint();
        jPanel3.revalidate();
    }//GEN-LAST:event_btnEncryptActionPerformed

    private void btnRecoverActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRecoverActionPerformed
        // TODO add your handling code here:


        //removing panel
        jPanel3.removeAll();
        jPanel3.repaint();
        jPanel3.revalidate();

        //adding panel
        jPanel3.add(jPanel6);
        jPanel3.repaint();
        jPanel3.revalidate();
    }//GEN-LAST:event_btnRecoverActionPerformed
////////////////////////////////////////////////////////////////////////////////

    Encryption e;
    String key ;
    int index ;
    File file;
    String path;

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed

        file = jFileChooser2.getSelectedFile();

        path = file.getAbsoluteFile().toString();


        index = encryptSelection.getSelectedIndex();

        key =  txtEncryptKey.getText();

        File test = new File(path);

        if (test.isFile()){
            e = new Encryption (key,path);
            switch (index){
                case 0:
                    e.caeserCipherEncrypt();
                    break;
                case 1:
                    e.vigenereCipherEncrypt();
                    break;
                case 2:
                    e.vectorOfPermutationEncrypt();
                    break;
                case 3:
                    e.manhattanCipherEncrypt();
                    break;

                default:
                    System.out.println("something went wrong");
            }
        }else if(test.isDirectory()){

//           File[] files = new File(path).listFiles();
//           String [] paths = new String[files.length];
//           for (int i = 0; i < files.length; i++) {
//
//               paths[i] = files[i].getAbsolutePath();
//
//           }
//
//           BatchEncrypt [] encThreads = new BatchEncrypt [paths.length];
//
//           for (int i = 0; i < encThreads.length; i++) {
//               encThreads[i] = new BatchEncrypt(index,paths[i],key);
//
//           }
//
//           for (int i = 0; i < encThreads.length; i++) {
//               encThreads[i].start();
//
//           }




            File[] files = new File(path).listFiles();
            ArrayList <String> paths = new ArrayList<String>();
            for (int i = 0; i < files.length; i++) {

                paths.add(files[i].getAbsolutePath());

            }

            BatchEncrypt t1;
            BatchEncrypt t2;
            BatchEncrypt t3;
            BatchEncrypt t4;
            ExecutorService service = Executors.newFixedThreadPool(4);

            Future<Boolean> future1 ;
            Future<Boolean> future2 ;
            Future<Boolean> future3 ;
            Future<Boolean> future4 ;

            String tmp;

            while(paths.size() >= 4){

                tmp=paths.get(0);
                paths.remove(0);
                t1 = new BatchEncrypt(index,tmp,key);

                tmp=paths.get(0);
                paths.remove(0);
                t2 = new BatchEncrypt(index,tmp,key);

                tmp=paths.get(0);
                paths.remove(0);
                t3 = new BatchEncrypt(index,tmp,key);

                tmp=paths.get(0);
                paths.remove(0);
                t4 = new BatchEncrypt(index,tmp,key);

                future1 = service.submit(t1);
                future2 = service.submit(t2);
                future3 = service.submit(t3);
                future4 = service.submit(t4);

            }

            if(paths.size() != 0){
                tmp=paths.get(0);
                paths.remove(0);
                t1 = new BatchEncrypt(index,tmp,key);
                future1 = service.submit(t1);


                if(paths.size() != 0){
                    tmp=paths.get(0);
                    paths.remove(0);
                    t2 = new BatchEncrypt(index,tmp,key);
                    future2 = service.submit(t2);

                }

                if(paths.size() != 0){
                    tmp=paths.get(0);
                    paths.remove(0);
                    t3 = new BatchEncrypt(index,tmp,key);
                    future3 = service.submit(t3);
                }

                if(paths.size() != 0){
                    tmp=paths.get(0);
                    paths.remove(0);
                    t4 = new BatchEncrypt(index,tmp,key);
                    future4 = service.submit(t4);
                }



            }


        }



        //clear Controls
        encryptSelection.setSelectedIndex(0);
        txtEncryptKey.setText("");


    }//GEN-LAST:event_jButton2ActionPerformed


    String recoveredKey ;
    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed


        file = jFileChooser3.getSelectedFile();

        path = file.getAbsoluteFile().toString();


        Encryption e = new Encryption ("filler",path);

       /*
       if(JtextKey.getText().equals("TheWorldGovernment")){

       key = "TheWorldGovernment";


       }

       else
           key = null;
*/



        recoveredKey = e.recoverKey(JtextKey.getText());
        System.out.println(recoveredKey);

        if(recoveredKey != null){
            txtRecover.setText(recoveredKey);
            txtRecover.setBackground(Color.WHITE);
        }
        else{
            txtRecover.setText("Wrong Admin Password!");
            txtRecover.setBackground(Color.RED);
        }



    }//GEN-LAST:event_jButton3ActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        file = jFileChooser1.getSelectedFile();

        path = file.getAbsoluteFile().toString();


        index = jComboBox1.getSelectedIndex();

        key =  jTextField1.getText();



        File test = new File(path);

        //if(test.equals("enc")){



        if ((test.isFile())){
            e = new Encryption (key,path);
            switch (index){
                case 0:
                    e.caeserCipherDecrypt();
                    break;
                case 1:
                    e.vigenereCipherDecrypt();
                    break;
                case 2:
                    e.vectorOfPermutationDecrypt();
                    break;
                case 3:
                    e.manhattanCipherDecrypt();
                    break;

                default:
                    System.out.println("something went wrong");
            }
        }else if (test.isDirectory())
        {
//
//           File[] files = new File(path).listFiles();
//           String [] paths = new String[files.length];
//           for (int i = 0; i < files.length; i++) {
//
//               paths[i] = files[i].getAbsolutePath();
//
//           }
//
//           BatchEncrypt [] encThreads = new BatchEncrypt [paths.length];
//
//           for (int i = 0; i < encThreads.length; i++) {
//               encThreads[i] = new BatchEncrypt(index,paths[i],key);
//
//           }
//
//           for (int i = 0; i < encThreads.length; i++) {
//               encThreads[i].start();
//
//           }
//


            File[] files = new File(path).listFiles();
            ArrayList <String> paths = new ArrayList<String>();
            for (int i = 0; i < files.length; i++) {

                paths.add(files[i].getAbsolutePath());

            }

            BatchDecrypt t1;
            BatchDecrypt t2;
            BatchDecrypt t3;
            BatchDecrypt t4;
            ExecutorService service = Executors.newFixedThreadPool(4);

            Future<Boolean> future1 ;
            Future<Boolean> future2 ;
            Future<Boolean> future3 ;
            Future<Boolean> future4 ;

            String tmp;

            while(paths.size() >= 4){

                tmp=paths.get(0);
                paths.remove(0);
                t1 = new BatchDecrypt(index,tmp,key);

                tmp=paths.get(0);
                paths.remove(0);
                t2 = new BatchDecrypt(index,tmp,key);

                tmp=paths.get(0);
                paths.remove(0);
                t3 = new BatchDecrypt(index,tmp,key);

                tmp=paths.get(0);
                paths.remove(0);
                t4 = new BatchDecrypt(index,tmp,key);

                future1 = service.submit(t1);
                future2 = service.submit(t2);
                future3 = service.submit(t3);
                future4 = service.submit(t4);

            }

            if(paths.size() != 0){
                tmp=paths.get(0);
                paths.remove(0);
                t1 = new BatchDecrypt(index,tmp,key);
                future1 = service.submit(t1);


                if(paths.size() != 0){
                    tmp=paths.get(0);
                    paths.remove(0);
                    t2 = new BatchDecrypt(index,tmp,key);
                    future2 = service.submit(t2);

                }

                if(paths.size() != 0){
                    tmp=paths.get(0);
                    paths.remove(0);
                    t3 = new BatchDecrypt(index,tmp,key);
                    future3 = service.submit(t3);
                }

                if(paths.size() != 0){
                    tmp=paths.get(0);
                    paths.remove(0);
                    t4 = new BatchDecrypt(index,tmp,key);
                    future4 = service.submit(t4);
                }



            }


        }



        //clear Controls
        jComboBox1.setSelectedIndex(0);
        jTextField1.setText("");

        // }

    }//GEN-LAST:event_jButton1ActionPerformed

    private void jComboBox1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBox1ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jComboBox1ActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(MainFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(MainFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(MainFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(MainFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new MainFrame().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextField JtextKey;
    private javax.swing.JButton btnDecrypt;
    private javax.swing.JButton btnEncrypt;
    private javax.swing.JButton btnRecover;
    private javax.swing.JComboBox<String> encryptSelection;
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JComboBox<String> jComboBox1;
    private javax.swing.JFileChooser jFileChooser1;
    private javax.swing.JFileChooser jFileChooser2;
    private javax.swing.JFileChooser jFileChooser3;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JPanel jPanel6;
    private javax.swing.JTextField jTextField1;
    private javax.swing.JTextField txtEncryptKey;
    private javax.swing.JTextField txtRecover;
    // End of variables declaration//GEN-END:variables
    private String getExtension(String path) {

        String extension;
        int i = path.lastIndexOf('.');
        if (i > 0) {
            extension = path.substring(i + 1);

            return extension;

        }else {
            return null;
        }


    }

}

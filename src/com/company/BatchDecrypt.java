/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.company;

import java.util.concurrent.Callable;



/**
 *
 * @author Abdulsalam Mansour
 */
class BatchDecrypt implements Callable <Boolean> {

    private int selection;
    private String path;
    private String key;

    public BatchDecrypt(int selection, String path, String key) {
        this.selection = selection;
        this.path = path;
        this.key = key;
    }



    @Override
    public Boolean call() throws Exception {
        Encryption e = new Encryption (key,path);

        switch (selection){
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

        return true;

    }


}


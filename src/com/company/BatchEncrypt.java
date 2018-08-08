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
class BatchEncrypt implements Callable <Boolean> {

    private int selection;
    private String path;
    private String key;

    public BatchEncrypt(int selection, String path, String key) {
        this.selection = selection;
        this.path = path;
        this.key = key;
    }



    @Override
    public Boolean call() throws Exception {
        Encryption e = new Encryption (key,path);

        switch (selection){
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

        return true;

    }


}


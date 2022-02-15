package hr.fer.kik.aes;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class Main {
    public static void main(String[] args) throws IOException {

        byte[] key = null;
        if(args.length > 3)
            key = args[3].getBytes(StandardCharsets.UTF_8);

        File file = new File(args[2]);

        //byte[] fileContent = Files.readAllBytes(file.toPath());
        //Files.write(file.toPath(), fileContent);

        if(args.length < 3){
            System.out.println("Neispravan unos argumenata. Primjer unosa: ecb/ctr enc/dec [datoteka] [ključ] [iv] *za CTR mode" );
            System.exit(1);
        }

        if(args[0].equals("ecb") && args[1].equals("enc")){
            byte[] fileContent = Files.readAllBytes(file.toPath());
            byte[] out = AES128.encryptECB(fileContent, key);

            Files.write(file.toPath(), out);
        }
        if(args[0].equals("ecb") && args[1].equals("dec")){
            byte[] fileContent = Files.readAllBytes(file.toPath());
            byte[] out = AES128.decryptECB(fileContent, key);

            Files.write(file.toPath(), out);
        }

        if(args[0].equals("ctr")){
            if(args.length < 5){
                System.out.println("Neispravan unos argumenata. Primjer unosa: ecb/ctr enc/dec [datoteka] [ključ] [iv] *za CTR mode" );
                System.exit(1);
            }
            byte[] iv = args[4].getBytes(StandardCharsets.UTF_8);
            byte[] fileContent = Files.readAllBytes(file.toPath());
            byte[] out = AES128.encryptCTR(fileContent, key, iv);

            Files.write(file.toPath(), out);
        }
    }
}

package pl.sygnity.sbe;

import pl.sygnity.sbe.security.auth.GenerateCSR;

public class CSRApp {

    public static void main(String[] args) {

        GenerateCSR generator = new GenerateCSR();

        generator.createCSR();

    }

}

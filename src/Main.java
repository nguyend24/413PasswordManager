public class Main {
    public static void main(String[] args) {
        VaultManager v = new VaultManager();
        Client c = new Client(v);

        c.createNewVault("duy", "hello world");
        c.createNewVault("michael", "secure password");
        c.deleteVault("duy", "hello world");
        c.createNewVault("duy", "hello world");
//        v.updateVault("duy", Client.hashMasterKey("hello world"), "{\"google\":Gasdoasdoas, \"amazon.com\":aasdasda}");
//        c.addVaultEntry("duy", "hello world", null);
    }
}

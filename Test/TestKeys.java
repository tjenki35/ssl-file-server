package Test;

import Errors.ResourceError;
import java.math.BigInteger;
import java.util.ArrayList;

/**
 * NOTE: THIS CLASS IS NOT USED IN THE ACTUAL PROGRAM This class contains
 * various key information for the Test.java class, which is used to test method
 * and class functionality
 */
public class TestKeys {

    //public exponents
    private static final String A_PEXP = "7";
    private static final String B_PEXP = "3";

    //public moduli
    private static final String A_PUN = "25039976173023539350939432462640680793811583645608094914318176923014458363143433148138558764948924468878592060120333573562079947069989099873848344152268656669910330053517787101125426369121511961006887932530944086060136048722219294513926358943162780326572397287475648129613588828672541050060218521905471235274454580064587256303390020931996313988901912456533179176242007608558053964533164544350254124469419398709554172255683160040583072797354526959000040244565606507176850289691768407195468204607346769408258879178989053443709643569441778871440898051707772411108052911976094134731834910071534470372659823442790172055587";
    private static final String B_PUN = "13319423989960578990461473243617030149029717248204259403472730976241583933236667020758929092804776918169361499125566127212669736839923832133632061348821751645884551142583961329093648126135114252928160003856134434452346270928311197310647417527964236768269062658160328382348474127435852952576634649048888505328359427460530862893682803010104112603087628056086266271134135953137958918750747993773658572489258143949867279115401918366521958617713395922630384141468039094802601290158765642959019670450228780107651530042471486073840092881115108057043707661054436002677575136109041318269276744568840993413604909042766732434469";

    private ArrayList<pub_info> ALL_INFO;

    protected final static String Server = "234";
    protected final static String Client = "235";

    /*
        These constuctors and sub-class/methods give an API to access "Public" information 
     */
    protected TestKeys() {
        ALL_INFO = new ArrayList<>();
        ALL_INFO.add(new pub_info(Client, new BigInteger(A_PEXP), new BigInteger(A_PUN)));
        ALL_INFO.add(new pub_info(Server, new BigInteger(B_PEXP), new BigInteger(B_PUN)));
    }

    protected pub_info get_info(String name) throws ResourceError {
        for (pub_info p : ALL_INFO) {
            if (p.id.equals(name)) {
                return p;
            }
        }
        throw new ResourceError("User not found : " + name);
    }

    protected class pub_info {

        protected pub_info(String name, BigInteger public_exponent, BigInteger public_modulus) {
            this.public_exponent_encrypt = public_exponent;
            this.public_modulus_encrypt = public_modulus;
            this.public_modulus_sign = public_modulus;
            this.public_exponent_sign = public_exponent;
            this.id = name;
        }
        protected BigInteger public_exponent_encrypt;
        protected BigInteger public_modulus_encrypt;
        protected BigInteger public_exponent_sign;
        protected BigInteger public_modulus_sign;

        protected String id;

    }
}

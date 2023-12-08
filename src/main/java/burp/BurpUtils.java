package burp;

import burp.api.montoya.MontoyaApi;
import de.usd.cstchef.view.View;
import de.usd.cstchef.view.filter.FilterState;

public class BurpUtils {

    private static BurpUtils instance;
    private MontoyaApi api;
    private View view;
    private FilterState filterState;

    public static BurpUtils getInstance() {
        if (BurpUtils.instance == null) {
            BurpUtils.instance = new BurpUtils();
        }
        return BurpUtils.instance;
    }

    private BurpUtils() {
    }

    public void init(MontoyaApi api) {
        this.api = api;
        this.filterState = new FilterState();
    }

    public MontoyaApi getApi() throws IllegalAccessError {
        if (this.api == null) {
            throw new IllegalAccessError("Only works within burpsuite");
        }
        return api;
    }

    public void setView(View view){
        this.view = view;
    }

    public View getView(){
        return view;
    }

    public FilterState getFilterState(){
        return filterState;
    }

    public void setFilterState(FilterState state){
        this.filterState = state;
    }

    public static boolean inBurp() {
        try {
            BurpUtils.getInstance().getApi();
            return true;
        } catch (IllegalAccessError e) {
            return false;
        }
    }

}

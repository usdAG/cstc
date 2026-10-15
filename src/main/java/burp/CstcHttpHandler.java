package burp;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils;
import de.usd.cstchef.view.RecipePanel;
import de.usd.cstchef.view.View;
import de.usd.cstchef.view.filter.FilterState;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

import static burp.api.montoya.core.ToolType.EXTENSIONS;

public class CstcHttpHandler implements HttpHandler {

    private View view;

    CstcHttpHandler(View view) {
        this.view = view;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if(requestToBeSent.toolSource().isFromTool(EXTENSIONS) && requestToBeSent.hasHeader("X-CSTC-79301f837932346cb067c568e27369bf")) {
            HttpRequest request = requestToBeSent.withRemovedHeader("X-CSTC-79301f837932346cb067c568e27369bf");
            return continueWith(request, Annotations.annotations("CSTC"));
        }

        ByteArray request = requestToBeSent.toByteArray();
        ByteArray modifiedRequest = request;
        boolean requestModified = false;

        for (RecipePanel recipePanel : getOrderedRecipePanels(FilterState.BurpOperation.OUTGOING,
                requestToBeSent.toolSource().toolType())) {
            ByteArray candidateRequest = recipePanel.bake(modifiedRequest, null);
            if (!Utils.isHttpRequest(candidateRequest)) {
                Logger.getInstance().err("CSTC recipe produced an invalid HTTP request. Leaving request unchanged.");
                return continueWith(requestToBeSent);
            }
            modifiedRequest = candidateRequest;
            requestModified = true;
        }

        if (!requestModified) {
            return continueWith(requestToBeSent);
        }

        return continueWith(HttpRequest.httpRequest(modifiedRequest).withService(requestToBeSent.httpService()));
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if(responseReceived.annotations().hasNotes() && responseReceived.annotations().notes().equals("CSTC")) {
            return continueWith(responseReceived);
        }

        ByteArray response = responseReceived.toByteArray();
        ByteArray modifiedResponse = response;
        boolean responseModified = false;

        for (RecipePanel recipePanel : getOrderedRecipePanels(FilterState.BurpOperation.INCOMING,
                responseReceived.toolSource().toolType())) {
            ByteArray candidateResponse = recipePanel.bake(modifiedResponse, responseReceived.initiatingRequest().toByteArray());
            if (!Utils.isHttpResponse(candidateResponse)) {
                Logger.getInstance().err("CSTC recipe produced an invalid HTTP response. Leaving response unchanged.");
                return continueWith(responseReceived);
            }
            modifiedResponse = candidateResponse;
            responseModified = true;
        }

        if (!responseModified) {
            return continueWith(responseReceived);
        }

        return continueWith(HttpResponse.httpResponse(modifiedResponse));
    }

    private List<RecipePanel> getOrderedRecipePanels(FilterState.BurpOperation operation, ToolType toolType) {
        List<OrderedRecipePanel> orderedRecipePanels = new ArrayList<OrderedRecipePanel>();
        int recipeIndex = 0;

        for (RecipePanel recipePanel : view.getFilterableRecipePanels()) {
            if (!recipePanel.getOperation().equals(operation)) {
                recipeIndex++;
                continue;
            }

            int selectionOrder = BurpUtils.getInstance().getFilterState()
                    .getFilterSelectionOrder(operation, recipePanel.getRecipeName(), toolType);
            if (selectionOrder <= 0) {
                recipeIndex++;
                continue;
            }

            orderedRecipePanels.add(new OrderedRecipePanel(recipePanel, selectionOrder, recipeIndex));
            recipeIndex++;
        }

        orderedRecipePanels.sort(Comparator
                .comparingInt(OrderedRecipePanel::getSelectionOrder)
                .thenComparingInt(OrderedRecipePanel::getRecipeIndex));

        List<RecipePanel> sortedRecipePanels = new ArrayList<RecipePanel>();
        for (OrderedRecipePanel orderedRecipePanel : orderedRecipePanels) {
            sortedRecipePanels.add(orderedRecipePanel.getRecipePanel());
        }

        return sortedRecipePanels;
    }

    private static class OrderedRecipePanel {
        private final RecipePanel recipePanel;
        private final int selectionOrder;
        private final int recipeIndex;

        private OrderedRecipePanel(RecipePanel recipePanel, int selectionOrder, int recipeIndex) {
            this.recipePanel = recipePanel;
            this.selectionOrder = selectionOrder;
            this.recipeIndex = recipeIndex;
        }

        private RecipePanel getRecipePanel() {
            return recipePanel;
        }

        private int getSelectionOrder() {
            return selectionOrder;
        }

        private int getRecipeIndex() {
            return recipeIndex;
        }
    }

}

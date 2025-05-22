package de.usd.cstchef.operations.utils;

import java.awt.Color;
import java.util.Timer;
import java.util.TimerTask;

import javax.swing.JProgressBar;
import javax.swing.JSpinner;
import javax.swing.UIManager;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Sleep", category = OperationCategory.UTILS, description = "Delay the recipe execution for this amount of milliseconds.")
public class Sleep extends Operation {

    private JSpinner millisecondsSpinner;
    public JProgressBar outputOfTimeLeft;
    private Timer timer;
    public int globalCounter;
    public int localCounter;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        globalCounter = (int) millisecondsSpinner.getValue();
        if(globalCounter == 0) return input;
        int fractOfGlobalCounter = globalCounter < 100 ? 1 : globalCounter / 100;
        localCounter = fractOfGlobalCounter;

        outputOfTimeLeft.setMinimum(0);
        outputOfTimeLeft.setMaximum(globalCounter);


        timer = new Timer();
        timer.scheduleAtFixedRate(new TimerTask() {

            @Override
            public void run() {
                setBackground(new Color(240, 240, 216));
                outputOfTimeLeft.setValue(localCounter);
                globalCounter = globalCounter - fractOfGlobalCounter; localCounter = localCounter + fractOfGlobalCounter;
                if(globalCounter == -fractOfGlobalCounter) {
                    setBackground(new Color(223, 240, 216));
                    timer.cancel();
                }
            }
            
        }, 0, fractOfGlobalCounter);

        
        return input;
    }

    public JProgressBar getProgressBar() {
        return this.outputOfTimeLeft;
    }

    public void createUI() {
        UIManager.put("ProgressBar.background", Color.LIGHT_GRAY);
        UIManager.put("ProgressBar.foreground", Color.DARK_GRAY);

        this.millisecondsSpinner = new JSpinner();
        this.addUIElement("Milliseconds to sleep", this.millisecondsSpinner);

        this.outputOfTimeLeft = new JProgressBar();
        this.addUIElement(null, outputOfTimeLeft, "outputLabel");

    }

}
package de.usd.cstchef.operations.utils;

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JProgressBar;
import javax.swing.JSpinner;
import javax.swing.UIManager;
import javax.swing.Timer;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.RecipePanel;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Sleep", category = OperationCategory.UTILS, description = "Delay the recipe execution for this amount of milliseconds.")
public class Sleep extends Operation {

    private JSpinner millisecondsSpinner;
    public JProgressBar outputOfTimeLeft;
    private Timer timer;
    public int elapsedTime;
    public int totalTime;


    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        if(timer != null) {
            timer.stop();
        }

        totalTime = (int) millisecondsSpinner.getValue();
        if(totalTime == 0) return input;
        int delay = totalTime < 1000 ? 1 : totalTime / 100;
        elapsedTime = 0;

        outputOfTimeLeft.setMinimum(0);
        outputOfTimeLeft.setMaximum(totalTime);


        timer = new Timer(delay, new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                elapsedTime += delay;
                outputOfTimeLeft.setValue(elapsedTime);

                if(elapsedTime >= totalTime) {
                    // Operation.defaultBgColor
                    setBackground(new Color(223, 240, 216));
                    timer.stop();
                    outputOfTimeLeft.setValue(0);
                }
            }
            
        });

        setBackground(new Color(240, 240, 216));
        timer.start();

        Thread.sleep((int)millisecondsSpinner.getValue());

        
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
        this.outputOfTimeLeft.setValue(0);
        this.outputOfTimeLeft.setStringPainted(true);
        this.addUIElement(null, outputOfTimeLeft, "outputLabel");

    }

}
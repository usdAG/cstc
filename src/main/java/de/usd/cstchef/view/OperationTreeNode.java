package de.usd.cstchef.view;

import javax.swing.tree.DefaultMutableTreeNode;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;

public class OperationTreeNode extends DefaultMutableTreeNode {

    private String name;
    private String toolTipText;
    private Class<? extends Operation> operationClass;

    public OperationTreeNode(Class<? extends Operation> operationClass) {
        super();
        OperationInfos infos = operationClass.getAnnotation(OperationInfos.class);
        this.name = infos.name();
        this.toolTipText = infos.description();

        this.operationClass = operationClass;
    }

    public String getToolTipText() {
        return this.toolTipText;
    }

    public Class<? extends Operation> getOperationClass() {
        return operationClass;
    }

    @Override
    public String toString() {
        return this.name;
    }
}

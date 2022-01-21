package de.usd.cstchef.view;

import java.awt.Container;
import javax.swing.JTree;
import javax.swing.tree.TreePath;

import de.usd.cstchef.operations.Operation;

public class AddOperationMouseAdapter extends OperationMouseAdapter {


    public AddOperationMouseAdapter(JTree source, Container target) {
        super(source, target);
    }

    @Override
    protected Operation getDraggedOperation(int x, int y) {
        TreePath draggedPath = ((JTree) this.source).getClosestPathForLocation(x, y);
        if (draggedPath != null) {
            Object node = draggedPath.getLastPathComponent();
            if (node.getClass().equals(OperationTreeNode.class)) {
                Class<? extends Operation> cls = ((OperationTreeNode) node).getOperationClass();
                try {
                    return cls.newInstance();
                } catch (InstantiationException | IllegalAccessException e) {
                }
            }
        }
        return null;
    }

}

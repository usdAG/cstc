package de.usd.cstchef.view;

import java.awt.event.MouseEvent;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;

import javax.swing.ImageIcon;
import javax.swing.JTree;
import javax.swing.plaf.basic.BasicTreeUI;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.MutableTreeNode;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;

import burp.Logger;
import de.usd.cstchef.Utils;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.filter.FilterState.BurpOperation;

public class OperationsTree extends JTree {

    private DefaultTreeModel model;
    private static ImageIcon nodeIcon = new ImageIcon(Operation.class.getResource("/operation.png"));
    private static ImageIcon openIcon = new ImageIcon(Operation.class.getResource("/folder_open.png"));
    private static ImageIcon closedIcon = new ImageIcon(Operation.class.getResource("/folder_closed.png"));
    private BurpOperation operation;

    public OperationsTree(BurpOperation operation) {
        super();
        this.operation = operation;
        this.setUI(new CustomTreeUI());
        this.model = (DefaultTreeModel) this.getModel();
        this.model.setRoot(this.createTree());
        this.setToolTipText("");
        DefaultTreeCellRenderer renderer = (DefaultTreeCellRenderer) this.getCellRenderer();
        renderer.setLeafIcon(nodeIcon);
        renderer.setClosedIcon(closedIcon);
        renderer.setOpenIcon(openIcon);
    }

    @Override
    public String getToolTipText(MouseEvent evt) {
        if (getRowForLocation(evt.getX(), evt.getY()) == -1) {
            return null;
        }

        TreePath curPath = getPathForLocation(evt.getX(), evt.getY());
        Object node = curPath.getLastPathComponent();

        if (node.getClass().equals(OperationTreeNode.class)) {
            return ((OperationTreeNode) node).getToolTipText();
        } else if (node.getClass().equals(DefaultMutableTreeNode.class)) {
            return null;
        }

        return "";
    }

    public void search(String text) {
        DefaultMutableTreeNode root = this.createTree();
        this.model.setRoot(root);

        if (text.trim().equals("")) {
            return;
        }

        ArrayList<DefaultMutableTreeNode> nodesToRemove = new ArrayList<>();
        Enumeration<TreeNode> e = root.breadthFirstEnumeration();
        while (e.hasMoreElements()) {
            DefaultMutableTreeNode nextNode = (DefaultMutableTreeNode) e.nextElement();
            if (!nextNode.toString().toLowerCase().contains(text.toLowerCase())) {
                if (nextNode.getChildCount() == 0) {
                    nodesToRemove.add(nextNode);
                }
            }
        }

        for (DefaultMutableTreeNode node : nodesToRemove) {
            this.removeNode(node);
        }

        nodesToRemove.clear();
        for (int i = 0; i < root.getChildCount(); i++) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) root.getChildAt(i);
            if (node.getChildCount() == 0) {
                nodesToRemove.add(node);
            }
        }

        for (DefaultMutableTreeNode node : nodesToRemove) {
            this.removeNode(node);
        }

        this.expandAll(new TreePath(root));
    }

    private void removeNode(TreeNode selNode) {
        if (selNode == null) {
            return;
        }

        MutableTreeNode parent = (MutableTreeNode) (selNode.getParent());
        if (parent == null) {
            return;
        }

        if (selNode.getChildCount() == 0) {
            this.model.removeNodeFromParent((MutableTreeNode) selNode);
        }
    }

    private DefaultMutableTreeNode createTree() {
        DefaultMutableTreeNode root = new DefaultMutableTreeNode();

        // add all categories
        HashMap<OperationCategory, DefaultMutableTreeNode> categoryNodes = new HashMap<>();
        for (OperationCategory category : OperationCategory.values()) {
            DefaultMutableTreeNode categoryNode = new DefaultMutableTreeNode(category.toString());
            root.add(categoryNode);
            categoryNodes.put(category, categoryNode);
        }

        // TODO add operations to categories - reflections do not work in burp :(
        // pass the operation parameter so that separate operation trees can be defined for incoming/outgoing/formatting
        Class<? extends Operation>[] operations = Utils.getOperations(this.operation);
        for (Class<? extends Operation> operation : operations) {
            OperationInfos operationInfos = operation.getAnnotation(OperationInfos.class);
            if (operationInfos == null) {
                if (!Modifier.isAbstract(operation.getModifiers())) {
                    Logger.getInstance().err("Found a operation without annotaion: " + operation);
                }
                continue;
            }

            OperationCategory category = operationInfos.category();
            DefaultMutableTreeNode parent = categoryNodes.get(category);

            OperationTreeNode newOperationNode = new OperationTreeNode(operation);
            parent.add(newOperationNode);
        }

        return root;
    }

    private void expandAll(TreePath path) {
        TreeNode node = (TreeNode) path.getLastPathComponent();

        if (node.getChildCount() >= 0) {
            Enumeration enumeration = node.children();
            while (enumeration.hasMoreElements()) {
                TreeNode n = (TreeNode) enumeration.nextElement();
                TreePath p = path.pathByAddingChild(n);

                expandAll(p);
            }
        }
        this.expandPath(path);
    }

    public class CustomTreeUI extends BasicTreeUI {
        @Override
        protected boolean shouldPaintExpandControl(javax.swing.tree.TreePath path, int row, boolean isExpanded,
                boolean hasBeenExpanded, boolean isLeaf) {
            return true; // Always display expand/collapse control
        }
    }
}

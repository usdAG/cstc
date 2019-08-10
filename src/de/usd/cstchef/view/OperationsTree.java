package de.usd.cstchef.view;

import java.awt.event.MouseEvent;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;

import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.MutableTreeNode;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;

import burp.Logger;
import de.usd.cstchef.Utils;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

public class OperationsTree extends JTree {
	
	private DefaultTreeModel model;
	
	public OperationsTree() {
		super();
		
		this.model = (DefaultTreeModel) this.getModel();
		this.model.setRoot(this.createTree());
		this.setToolTipText("");
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
		Class<? extends Operation>[] operations = Utils.getOperations();
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
	
}

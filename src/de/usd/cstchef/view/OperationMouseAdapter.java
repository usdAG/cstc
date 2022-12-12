package de.usd.cstchef.view;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.dnd.DragSource;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.Window.Type;
import java.util.Objects;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JWindow;
import javax.swing.SwingUtilities;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;

/*
 * Based on:
 * 	https://stackoverflow.com/questions/27245283/java-drag-and-drop-to-change-the-order-of-panels
 */
public abstract class OperationMouseAdapter extends MouseAdapter {

	private static final Rectangle R1 = new Rectangle();
	private static final Rectangle R2 = new Rectangle();

	private static Rectangle prevRect;

	private final JWindow window = new JWindow();
	private Container panelPreview;
	private JLabel windowPreviewLbl;
	private JLabel panelPreviewLbl;

	private Point startPt;
	private Point dragOffset;
	private final int gestureMotionThreshold = DragSource.getDragThreshold();

	protected Container source;
	protected Container target;
	private RecipeStepPanel currentTargetPanel;

	private Operation draggedOperation;

	public OperationMouseAdapter(Container source, Container target) {
		super();
		this.source = source;
		this.target = target;
		window.setSize(300, 35);
		window.setLocationRelativeTo(null);
		window.setBackground(new Color(0, true));
		window.setVisible(false);
		window.setType(Type.POPUP);

		Container windowPreview = createPreview("My Preview");
		windowPreviewLbl = (JLabel) windowPreview.getComponent(0);
		window.add(windowPreview);
		panelPreview = createPreview("My Preview");
		panelPreviewLbl = (JLabel) panelPreview.getComponent(0);

		dragOffset = new Point(window.getWidth() / 3, window.getHeight() / 2);
	}

	private Container createPreview(String title) {
		Box previewBox = Box.createHorizontalBox();
		previewBox.setOpaque(true);
		previewBox.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		previewBox.setBackground(new Color(127, 237, 247, 255));

		JLabel previewLbl = new JLabel(title);
		previewLbl.setForeground(new Color(58, 135, 173));

		previewBox.add(previewLbl);
		return previewBox;
	}

	private void startDragging(Point pt) {
		OperationInfos opInfos = this.draggedOperation.getClass().getAnnotation(OperationInfos.class);
		if (opInfos == null) {
			return;
		}

		String name = opInfos.name();
		windowPreviewLbl.setText(name);
		panelPreviewLbl.setText(name);

		updateWindowLocation(pt, this.source);
		window.setVisible(true);
	}

	private void updateWindowLocation(Point pt, Container parent) {
		Point p = new Point(pt.x - dragOffset.x, pt.y - dragOffset.y);
		SwingUtilities.convertPointToScreen(p, parent);
		window.setLocation(p);
	}

	private int getTargetIndex(Rectangle r, Point pt, int i, boolean previewIndexSmaller) {
		int ht2 = (int) (0.5 + r.height * 0.5);
		R1.setBounds(r.x, r.y, r.width, ht2);
		R2.setBounds(r.x, r.y + ht2, r.width, ht2);
		if (R1.contains(pt)) {
			prevRect = R1;
			return previewIndexSmaller ? i - 1 : i - 1 > 0 ? i : 0;
		} else if (R2.contains(pt)) {
			prevRect = R2;
			return i;
		}
		return -1;
	}

	private void addComponent(RecipeStepPanel line, Component comp, int idx) {
		line.removeComponent(comp);
		line.addComponent(comp, idx);
	}

	@Override
	public void mousePressed(MouseEvent e) {
		this.startPt = e.getPoint();
	}
	
	protected abstract Operation getDraggedOperation(int x, int y);
	
	@Override
	public void mouseDragged(MouseEvent e) {
		Point pt = e.getPoint();
		JComponent parent = (JComponent) e.getComponent();
		
		// not yet dragging and motion > threshold
		if (this.draggedOperation == null && startPt != null) {
			double a = Math.pow(pt.x - startPt.x, 2);
			double b = Math.pow(pt.y - startPt.y, 2);
			if (Math.sqrt(a + b) > gestureMotionThreshold) {
				this.draggedOperation = this.getDraggedOperation(startPt.x, startPt.y);
				if (this.draggedOperation != null) {
					startDragging(pt);
				}
			}
			return;
		}

		// dragging, but no component was created
		if (!window.isVisible() || draggedOperation == null) {
			return;
		}

		pt = SwingUtilities.convertPoint(parent, e.getPoint(), this.target);
		updateWindowLocation(pt, this.target);

		Component targetLine = this.target.getComponentAt(pt);

		// changed the target, remove the old preview
		if (currentTargetPanel != null) {
			if (targetLine == null || !targetLine.equals(currentTargetPanel)) {
				this.currentTargetPanel.removeComponent(panelPreview);
				this.currentTargetPanel = null;
			}
		}

		// we have no valid target
		if (targetLine == null || !(targetLine instanceof RecipeStepPanel)) {
			return;
		}

		RecipeStepPanel targetPanel = (RecipeStepPanel) this.target.getComponentAt(pt);
		this.currentTargetPanel = targetPanel;

		JPanel operationsPanel = currentTargetPanel.getOperationsPanel();
		pt = SwingUtilities.convertPoint(this.target, pt, operationsPanel);

		if (prevRect != null && prevRect.contains(pt)) {
			return;
		}

		boolean gotPreview = false;
		for (int i = 0; i < operationsPanel.getComponentCount(); i++) {
			Component comp = operationsPanel.getComponent(i);
			Rectangle r = comp.getBounds();
			// inside our gap, do nothing
			if (Objects.equals(comp, panelPreview)) {
				if (r.contains(pt)) {
					return;
				} else {
					gotPreview = true;
					continue;
				}
			} 
			
			int tgt;
			if (!(comp instanceof Operation)) { //this is the dummy panel
				int count = operationsPanel.getComponentCount();
				tgt = count > 1 ? operationsPanel.getComponentCount() - 2 : 0;
			} else {
				tgt = getTargetIndex(r, pt, i, gotPreview);				
			}

			if (tgt >= 0) {
				addComponent(currentTargetPanel, panelPreview, tgt);
				return;
			}
		}
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		startPt = null;

		// no dragging
		if (!window.isVisible() || draggedOperation == null) {
			return;
		}
		int addIndex = -1;

		// get the index of the preview element
		if (currentTargetPanel != null) {
			JPanel operationsPanel = this.currentTargetPanel.getOperationsPanel();
			for (int i = 0; i < operationsPanel.getComponentCount(); i++) {
				Component comp = operationsPanel.getComponent(i);
				if (comp.equals(this.panelPreview)) {
					addIndex = i;
					break;
				}
			}
			// remove preview from panel
			currentTargetPanel.removeComponent(this.panelPreview);
		}
		
		if (addIndex != -1) {
			currentTargetPanel.addComponent(this.draggedOperation, addIndex);
		}
		
		this.draggedOperation = null;
		prevRect = null;
		this.startPt = null;
		this.window.setVisible(false);
		this.currentTargetPanel = null;
	}
}

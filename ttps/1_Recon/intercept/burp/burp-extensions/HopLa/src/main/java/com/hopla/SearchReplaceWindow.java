package com.hopla;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Theme;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.Highlighter;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.event.InputEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.geom.Rectangle2D;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.hopla.Constants.DEBUG;
import static com.hopla.Utils.generateJFrame;

public class SearchReplaceWindow {
    private static final int FRAME_MARGIN = 10;
    private final JCheckBox regexCheck = new JCheckBox("Regex");
    private final JCheckBox caseCheck = new JCheckBox("Case sensitive");
    private final JButton replaceAllButton = new JButton("Replace All");
    private final JLabel statusLabel = new JLabel(" ");
    private final MontoyaApi api;
    private final java.util.List<int[]> matchPositions = new java.util.ArrayList<>();
    private final DocumentListener documentListener;
    private Highlighter highlighter;
    private MessageEditorHttpRequestResponse messageEditor;
    private JTextField searchField;
    private JTextField replaceField;
    private int currentMatchIndex = -1;
    private JTextComponent source;
    private JFrame frame;

    public SearchReplaceWindow(MontoyaApi api) {
        this.api = api;
        this.documentListener = new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                highlightSearch();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                highlightSearch();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
            }

        };
    }

    public void attach(MessageEditorHttpRequestResponse messageEditor, InputEvent event, String input) {
        this.messageEditor = messageEditor;

        if (frame != null) {
            frame.dispose();
        }
        frame = generateJFrame();
        frame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);

        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                SearchReplaceWindow.this.dispose();
            }
        });

        this.source = (JTextComponent) event.getSource();
        highlighter = source.getHighlighter();

        JPanel panel = new JPanel();
        frame.getContentPane().add(panel);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel label1 = new JLabel("Search:");
        label1.setPreferredSize(new Dimension(80, 20));

        row1.add(label1);
        searchField = new JTextField(input, 20);
        row1.add(searchField);

        searchField.getDocument().addDocumentListener(documentListener);
        source.getDocument().addDocumentListener(documentListener);
        if (!input.isEmpty()) {
            highlightSearch();
        }

        row1.add(regexCheck);
        row1.add(caseCheck);
        JButton searchButton = new JButton("Search");
        row1.add(searchButton);
        JButton nextButton = new JButton("Next");
        JButton prevButton = new JButton("Previous");

        row1.add(prevButton);
        row1.add(nextButton);

        nextButton.addActionListener(e -> findNext());
        prevButton.addActionListener(e -> findPrevious());


        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel label2 = new JLabel("Replace:");
        label2.setPreferredSize(new Dimension(80, 20));
        row2.add(label2);
        replaceField = new JTextField(20);
        row2.add(replaceField);
        JButton replaceButton = new JButton("Replace");
        row2.add(replaceButton);
        row2.add(replaceAllButton);


        JPanel row3 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row3.add(statusLabel);

        panel.add(row1);
        panel.add(row2);
        panel.add(row3);

        searchButton.addActionListener(e -> search());
        caseCheck.addActionListener(e -> highlightSearch());
        regexCheck.addActionListener(e -> highlightSearch());
        replaceButton.addActionListener(e -> replaceOne());
        replaceAllButton.addActionListener(e -> replaceAll());

        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                removeHighlights();
            }
        });
        frame.pack();

        Point mousePos = MouseInfo.getPointerInfo().getLocation();
        mousePos.x += FRAME_MARGIN;
        mousePos.y += frame.getHeight() / 2;

        frame.setLocation(mousePos);
        frame.setVisible(true);
    }

    public void dispose() {
        if (frame != null) {
            frame.dispose();
        }
        if (source != null) {
            if (highlighter != null) {
                removeHighlights();
            }
            source.getDocument().removeDocumentListener(documentListener);
        }
    }

    private void removeHighlights() {
        Highlighter highlighter = source.getHighlighter();
        Highlighter.Highlight[] highlights = highlighter.getHighlights();

        for (Highlighter.Highlight h : highlights) {
            highlighter.removeHighlight(h);
        }
    }

    private String getContent() {
        return source.getText();
    }

    private void search() {
        highlightSearch();
        if (matchPositions.isEmpty()) return;
        scrollToCurrentMatch();
    }

    private void highlightSearch() {
        removeHighlights();
        matchPositions.clear();
        currentMatchIndex = -1;

        String searchText = searchField.getText();
        if (searchText.isEmpty()) return;

        Pattern pattern = buildPattern(searchText);
        Matcher matcher = pattern.matcher(getContent());

        int count = 0;
        while (matcher.find()) {
            if (DEBUG) {
                HopLa.montoyaApi.logging().logToOutput("HighlightSearch: " + matcher.start() + " " + matcher.end());
            }

            matchPositions.add(new int[]{matcher.start(), matcher.end()});
            count++;
        }

        if (count > 0) {
            currentMatchIndex = 0;
            highlightMatches();
            statusLabel.setText(count + " founds");
        } else {
            statusLabel.setText("Not found");
        }
    }

    private void highlightMatches() {
        boolean isDarkMode = this.api.userInterface().currentTheme() == Theme.DARK;
        Highlighter.HighlightPainter currentPainter = new HighlightPainter(this.api.userInterface().swingUtils().colorForHighLight(
                isDarkMode ? HighlightColor.CYAN : HighlightColor.ORANGE
        ));
        Highlighter.HighlightPainter otherPainter = new HighlightPainter(this.api.userInterface().swingUtils().colorForHighLight(
                isDarkMode ? HighlightColor.BLUE : HighlightColor.YELLOW
        ));

        removeHighlights();
        for (int i = 0; i < matchPositions.size(); i++) {
            int[] pos = matchPositions.get(i);
            Highlighter.HighlightPainter painter = (i == currentMatchIndex) ? currentPainter : otherPainter;
            try {
                highlighter.addHighlight(pos[0], pos[1], painter);
            } catch (BadLocationException e) {
                HopLa.montoyaApi.logging().logToError("Highlighter add error: " + e.getMessage());
            }
        }
    }

    private void findNext() {
        if (matchPositions.isEmpty()) return;
        currentMatchIndex = (currentMatchIndex + 1) % matchPositions.size();
        highlightMatches();
        scrollToCurrentMatch();
    }

    private void findPrevious() {
        if (matchPositions.isEmpty()) return;
        currentMatchIndex = (currentMatchIndex - 1 + matchPositions.size()) % matchPositions.size();
        highlightMatches();
        scrollToCurrentMatch();
    }

    private void scrollToCurrentMatch() {
        if (currentMatchIndex < 0 || currentMatchIndex >= matchPositions.size()) return;
        int[] pos = matchPositions.get(currentMatchIndex);
        source.setCaretPosition(pos[0]);
        source.requestFocusInWindow();
    }

    private void replaceOne() {
        if (matchPositions.isEmpty() || currentMatchIndex < 0) {
            statusLabel.setText("Not found");
            return;
        }

        int[] pos = matchPositions.get(currentMatchIndex);
        int start = pos[0];
        int end = pos[1];
        String replaceText = replaceField.getText();

        String updated = getContent().substring(0, start) + replaceText + getContent().substring(end);
        removeHighlights();
        updateSource(updated);
        SwingUtilities.invokeLater(this::highlightSearch);
        SwingUtilities.invokeLater(() -> {
            source.setCaretPosition(pos[0] + replaceText.length());
        });
    }

    private void updateSource(String content) {
        HttpRequest patched_request = HttpRequest.httpRequest(content);
        messageEditor.setRequest(patched_request);
    }

    private void replaceAll() {
        String searchText = searchField.getText();
        String replaceText = replaceField.getText();
        if (searchText.isEmpty()) return;

        Pattern pattern = buildPattern(searchText);
        Matcher matcher = pattern.matcher(getContent());

        int count = 0;
        StringBuilder result = new StringBuilder();
        while (matcher.find()) {
            matcher.appendReplacement(result, Matcher.quoteReplacement(replaceText));
            count++;
        }
        matcher.appendTail(result);
        int pos = source.getCaretPosition();
        if (count > 0) {
            removeHighlights();
            updateSource(result.toString());
            statusLabel.setText(count + " replaced");
            SwingUtilities.invokeLater(this::highlightSearch);
            source.setCaretPosition(pos);
        } else {
            statusLabel.setText("Not found");
        }
    }

    private Pattern buildPattern(String searchText) {
        int flags = caseCheck.isSelected() ? 0 : Pattern.CASE_INSENSITIVE;
        if (regexCheck.isSelected()) {
            return Pattern.compile(searchText, flags);
        } else {
            return Pattern.compile(Pattern.quote(searchText), flags);
        }
    }

    // Fix start line bug
    static class HighlightPainter implements Highlighter.HighlightPainter {
        private final Color color;

        public HighlightPainter(Color color) {
            this.color = color;
        }

        @Override
        public void paint(Graphics g, int p0, int p1, Shape bounds, JTextComponent c) {
            try {

                Rectangle2D r0 = c.modelToView2D(p0);
                Rectangle2D r1 = c.modelToView2D(p1);

                if (r0 == null || r1 == null) return;

                double x = r0.getX();
                double y = r0.getY();
                double width = r1.getX() - r0.getX();
                double height = r0.getHeight();

                if (width <= 0) width = 1; // fallback minimal

                Graphics2D g2 = (Graphics2D) g;
                g2.setColor(color);
                g2.fill(new Rectangle2D.Double(x, y, width, height));
            } catch (BadLocationException ex) {
                HopLa.montoyaApi.logging().logToError("Highlighter painter paint: " + ex.getMessage());

            }
        }
    }
}
/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.parosproxy.paros.core.scanner;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.core.scanner.InputVector;

/**
 * Variant used for "multipart/form-data" POST request handling. Takes all parameters passed inside
 * the form-data structure and sets them for injection.
 */
public class VariantMultipartFormParameters implements Variant {

    private static final Logger LOGGER = LogManager.getLogger(VariantMultipartFormParameters.class);
    private static final String DOUBLE_HYPHEN = "--";
    private static final Pattern FIELD_NAME_PATTERN =
            Pattern.compile(
                    "\\s*content-disposition\\s*:.*\\s+name\\s*\\=?\\s*\\\"?(?<name>.[^;\\\"\\n]*)\\\"?\\;?.*",
                    Pattern.CASE_INSENSITIVE);
    private static final Pattern FIELD_VALUE_PATTERN = Pattern.compile("[\\r\\n]{2}(?<value>.*)");
    private static final Pattern FILENAME_PART_PATTERN =
            Pattern.compile(
                    "\\s*content-disposition\\s*:.*filename\\s*\\=?\\s*\\\"?(?<filename>.[^;\"\\n]*)\\\"?\\;?.*",
                    Pattern.CASE_INSENSITIVE);
    // http://fiddle.re/etxbnd (Click Java, set case insensitive, and hit "test")
    private static final Pattern CONTENTTYPE_PART_PATTERN =
            Pattern.compile(
                    "\\s*content-disposition.*content-type\\s*:\\s*\\s*\\\"?(?<contenttype>.[^;\"\\r\\n]*)\\\"?\\;?.*",
                    Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    // http://www.regexplanet.com/share/index.html?share=yyyyyythear (Click Java, set case
    // insensitive & DOTALL, and hit "test")

    private List<NameValuePair> params = Collections.emptyList();
    private final List<MultipartFormParameter> multiPartParams = new ArrayList<>();

    private static final String SHORT_NAME = "multipart";

    @Override
    public String getShortName() {
        return SHORT_NAME;
    }

    @Override
    public void setMessage(HttpMessage msg) {
        if (msg == null) {
            throw new IllegalArgumentException("Parameter message must not be null.");
        }

        String contentType = msg.getRequestHeader().getNormalisedContentTypeValue();
        if (contentType == null || !contentType.startsWith("multipart/form-data")) {
            return;
        }

        try {
            parseImpl(msg, msg.getRequestHeader().getHeader(HttpHeader.CONTENT_TYPE));
        } catch (Exception e) {
            LOGGER.error("An error occurred while parsing multipart content:", e);
        }
    }

    private void parseImpl(HttpMessage msg, String contentType) {
        LOGGER.debug("Starting multipart form data parsing");
        multiPartParams.clear();
        String bareBoundary = getBoundary(contentType, msg);
        if (bareBoundary == null) {
            LOGGER.debug("No boundary found in content type, aborting parsing");
            return;
        }
        LOGGER.debug("Extracted boundary: {}", bareBoundary);

        String requestBody = msg.getRequestBody().toString();
        String boundaryCrlf = bareBoundary + HttpHeader.CRLF;
        String[] parts = requestBody.split(Pattern.quote(boundaryCrlf));
        LOGGER.debug("Split request body into {} parts", parts.length);

        List<NameValuePair> extractedParameters = new ArrayList<>();
        int position = 0;
        int offset = 0;

        for (String part : parts) {
            if (StringUtils.isBlank(part)) {
                LOGGER.debug("Skipping blank part at position {}", position);
                position++;
                // Match original: offset += part.length() where part is "" (empty), so offset stays same
                offset += part.length();
                continue;
            }

            // Match original behavior: modify part in place to include boundary
            // This matches: part = boundaryCrlf + part;
            String originalPart = part;
            String fullPart = boundaryCrlf + part;
            
            ParsedPart parsedPart = parsePart(originalPart, fullPart, boundaryCrlf, bareBoundary, offset, position);
            if (parsedPart == null) {
                LOGGER.debug("Part at position {} could not be parsed, skipping", position);
                position++;
                // Match original: offset += part.length() where part is the modified one
                offset += fullPart.length();
                continue;
            }

            extractedParameters.addAll(parsedPart.nameValuePairs());
            multiPartParams.addAll(parsedPart.multipartParameters());

            position = parsedPart.nextPosition();
            // Match original: offset += part.length() where part is modified (boundaryCrlf + originalPart)
            offset += fullPart.length();
        }

        params = Collections.unmodifiableList(extractedParameters);
        LOGGER.debug("Parsing complete. Extracted {} parameters", params.size());
    }

    /**
     * Parses a single multipart form data part.
     *
     * @param part the raw part string (without boundary)
     * @param fullPart the part string with boundary prefix
     * @param boundaryCrlf the boundary with CRLF
     * @param bareBoundary the boundary without CRLF
     * @param offset the current offset in the request body (points to start of boundary)
     * @param position the current parameter position
     * @return parsed part data or null if parsing fails
     */
    private ParsedPart parsePart(String part, String fullPart, String boundaryCrlf, String bareBoundary, int offset, int position) {
        int headerSeparatorIndex = part.indexOf(HttpHeader.CRLF + HttpHeader.CRLF);
        if (headerSeparatorIndex < 0) {
            LOGGER.debug("Part missing header separator (CRLF+CRLF), skipping");
            return null;
        }

        String partHeaderLine = part.substring(0, headerSeparatorIndex);
        boolean isFileParam = partHeaderLine.contains("filename=");
        LOGGER.debug("Parsing part - isFileParam: {}, header length: {}", isFileParam, partHeaderLine.length());
        String fieldName = extractFieldName(partHeaderLine);
        if (fieldName == null) {
            LOGGER.debug("Could not extract field name from part header");
            return null;
        }

        FieldValue fieldValue = extractFieldValue(fullPart, boundaryCrlf, partHeaderLine, bareBoundary);
        LOGGER.debug("Extracted field - name: {}, cleaned value length: {}, raw value length: {}",
                fieldName, fieldValue.cleanedValue().length(), fieldValue.rawValue().length());

        List<NameValuePair> nameValuePairs = new ArrayList<>();
        List<MultipartFormParameter> multipartParams = new ArrayList<>();

        // Match original: offset points to start of boundary, fullPart includes boundary
        // So valueStart = offset + position of CRLF+CRLF in fullPart + 4
        int valueStart = offset + fullPart.indexOf(HttpHeader.CRLF + HttpHeader.CRLF) + 4; // 4 for two CRLFs
        int valueEnd = valueStart + fieldValue.cleanedValue().length();

        int nextPosition;
        if (isFileParam) {
            int fileContentPosition = processFileParameter(
                    fullPart, fieldName, fieldValue, offset, position,
                    nameValuePairs, multipartParams, valueStart, valueEnd);
            // For file params, next position is file content position + 1
            nextPosition = fileContentPosition + 1;
        } else {
            processRegularParameter(
                    fieldName, fieldValue, position, valueStart, valueEnd,
                    nameValuePairs, multipartParams);
            // For regular params, next position is current position + 1
            nextPosition = position + 1;
        }

        int nextOffset = offset + part.length();

        return new ParsedPart(nameValuePairs, multipartParams, nextPosition, nextOffset);
    }

    /**
     * Extracts the field name from a part header line.
     *
     * @param partHeaderLine the header line of the part
     * @return the field name or null if not found
     */
    private String extractFieldName(String partHeaderLine) {
        Matcher nameMatcher = FIELD_NAME_PATTERN.matcher(partHeaderLine);
        if (!nameMatcher.find()) {
            LOGGER.debug("Field name pattern not found in header: {}", partHeaderLine);
            return null;
        }
        return nameMatcher.group("name");
    }

    /**
     * Extracts the field value from a full part string.
     *
     * @param fullPart the complete part including boundary
     * @param boundaryCrlf the boundary with CRLF
     * @param partHeaderLine the header line of the part
     * @param bareBoundary the boundary without CRLF
     * @return a record containing both the cleaned value (for NameValuePair) and raw value (for MultipartFormParameter)
     */
    private FieldValue extractFieldValue(String fullPart, String boundaryCrlf, String partHeaderLine, String bareBoundary) {
        Matcher valueMatcher = FIELD_VALUE_PATTERN.matcher(fullPart);
        valueMatcher.find();
        if (StringUtils.isBlank(valueMatcher.group("value"))) {
            // Need to skip one find for some reason...
            // https://regex101.com/r/4ig6Wk/1
            // http://fiddle.re/23cudd (Click Java, hit "test")
            valueMatcher.find();
        }
        String rawValue = valueMatcher.group("value");

        // Value doesn't include boundary, headerline, or double CRLF
        String cleanedValue = fullPart.replaceAll(
                Pattern.quote(boundaryCrlf + partHeaderLine) + HttpHeader.CRLF + HttpHeader.CRLF,
                "");
        // Strip final boundary
        cleanedValue = cleanedValue.replaceAll(
                HttpHeader.CRLF + "(" + Pattern.quote(bareBoundary) + DOUBLE_HYPHEN + HttpHeader.CRLF + ")?$",
                "");
        return new FieldValue(cleanedValue, rawValue);
    }

    /**
     * Record to hold both cleaned and raw field values.
     */
    private record FieldValue(String cleanedValue, String rawValue) {}

    /**
     * Processes a regular (non-file) multipart parameter.
     *
     * @param fieldName the field name
     * @param fieldValue the field value (both cleaned and raw)
     * @param position the parameter position
     * @param valueStart the start offset of the value
     * @param valueEnd the end offset of the value
     * @param nameValuePairs the list to add the NameValuePair to
     * @param multipartParams the list to add the MultipartFormParameter to
     */
    private void processRegularParameter(
            String fieldName, FieldValue fieldValue, int position,
            int valueStart, int valueEnd,
            List<NameValuePair> nameValuePairs, List<MultipartFormParameter> multipartParams) {
        LOGGER.debug("Processing regular parameter - name: {}, position: {}, start: {}, end: {}",
                fieldName, position, valueStart, valueEnd);

        nameValuePairs.add(new NameValuePair(
                NameValuePair.TYPE_MULTIPART_DATA_PARAM,
                fieldName,
                fieldValue.cleanedValue(),
                position));

        multipartParams.add(new MultipartFormParameter(
                fieldName,
                fieldValue.rawValue(),
                valueStart,
                valueEnd,
                position,
                MultipartFormParameter.Type.GENERAL));
    }

    /**
     * Processes a file multipart parameter, extracting filename, content-type, and file content.
     *
     * @param fullPart the complete part including boundary
     * @param fieldName the field name
     * @param fieldValue the field value (file content, both cleaned and raw)
     * @param offset the current offset in the request body
     * @param position the current parameter position
     * @param nameValuePairs the list to add NameValuePairs to
     * @param multipartParams the list to add MultipartFormParameters to
     * @param valueStart the start offset of the value
     * @param valueEnd the end offset of the value
     * @return the file content position (used to calculate next position)
     */
    private int processFileParameter(
            String fullPart, String fieldName, FieldValue fieldValue,
            int offset, int position,
            List<NameValuePair> nameValuePairs, List<MultipartFormParameter> multipartParams,
            int valueStart, int valueEnd) {
        LOGGER.debug("Processing file parameter - name: {}, position: {}", fieldName, position);

        // File content parameter (position + 2 to leave room for filename and content-type)
        int fileContentPosition = position + 2;
        nameValuePairs.add(new NameValuePair(
                NameValuePair.TYPE_MULTIPART_DATA_FILE_PARAM,
                fieldName,
                fieldValue.cleanedValue(),
                fileContentPosition));

        multipartParams.add(new MultipartFormParameter(
                fieldName,
                fieldValue.rawValue(),
                valueStart,
                valueEnd,
                fileContentPosition,
                MultipartFormParameter.Type.GENERAL));

        // Extract filename
        String filename = extractFilename(fullPart);
        if (filename != null) {
            int filenamePosition = position;
            int filenameStart = offset + fullPart.indexOf(filename);
            int filenameEnd = filenameStart + filename.length();

            LOGGER.debug("Extracted filename - name: {}, filename: {}, position: {}, start: {}, end: {}",
                    fieldName, filename, filenamePosition, filenameStart, filenameEnd);

            nameValuePairs.add(nameValuePairs.size() - 1, new NameValuePair(
                    NameValuePair.TYPE_MULTIPART_DATA_FILE_NAME,
                    fieldName,
                    filename,
                    filenamePosition));

            multipartParams.add(multipartParams.size() - 1, new MultipartFormParameter(
                    fieldName,
                    filename,
                    filenameStart,
                    filenameEnd,
                    filenamePosition,
                    MultipartFormParameter.Type.FILE_NAME));
        }

        // Extract content-type
        String contentType = extractContentType(fullPart);
        if (contentType != null) {
            int contentTypePosition = position + 1;
            int contentTypeStart = offset + fullPart.indexOf(contentType);
            int contentTypeEnd = contentTypeStart + contentType.length();

            LOGGER.debug("Extracted content-type - name: {}, content-type: {}, position: {}, start: {}, end: {}",
                    fieldName, contentType, contentTypePosition, contentTypeStart, contentTypeEnd);

            nameValuePairs.add(nameValuePairs.size() - 1, new NameValuePair(
                    NameValuePair.TYPE_MULTIPART_DATA_FILE_CONTENTTYPE,
                    fieldName,
                    contentType,
                    contentTypePosition));

            multipartParams.add(multipartParams.size() - 1, new MultipartFormParameter(
                    fieldName,
                    contentType,
                    contentTypeStart,
                    contentTypeEnd,
                    contentTypePosition,
                    MultipartFormParameter.Type.FILE_CONTENT_TYPE));
        }

        return fileContentPosition;
    }

    /**
     * Extracts the filename from a file part.
     *
     * @param fullPart the complete part including boundary
     * @return the filename or null if not found
     */
    private String extractFilename(String fullPart) {
        Matcher filenameMatcher = FILENAME_PART_PATTERN.matcher(fullPart);
        if (!filenameMatcher.find()) {
            LOGGER.debug("Filename pattern not found in part");
            return null;
        }
        return filenameMatcher.group("filename");
    }

    /**
     * Extracts the content-type from a file part.
     *
     * @param fullPart the complete part including boundary
     * @return the content-type or null if not found
     */
    private String extractContentType(String fullPart) {
        Matcher contentTypeMatcher = CONTENTTYPE_PART_PATTERN.matcher(fullPart);
        if (!contentTypeMatcher.find()) {
            LOGGER.debug("Content-type pattern not found in part");
            return null;
        }
        return contentTypeMatcher.group("contenttype");
    }

    /**
     * Record to hold parsed part data.
     */
    private record ParsedPart(
            List<NameValuePair> nameValuePairs,
            List<MultipartFormParameter> multipartParameters,
            int nextPosition,
            int nextOffset) {}

    @Override
    public List<NameValuePair> getParamList() {
        return params;
    }

    @Override
    public String setParameter(
            HttpMessage msg, NameValuePair originalPair, String name, String value) {
        return setParameter(
                msg,
                Collections.singletonList(originalPair.getPosition()),
                Collections.singletonList(value));
    }

    @Override
    public String setEscapedParameter(
            HttpMessage msg, NameValuePair originalPair, String name, String value) {
        return setParameter(
                msg,
                Collections.singletonList(originalPair.getPosition()),
                Collections.singletonList(value));
    }

    @Override
    public void setParameters(HttpMessage msg, List<InputVector> inputVectors) {
        this.setParameter(
                msg,
                inputVectors.stream().map(InputVector::getPosition).collect(Collectors.toList()),
                inputVectors.stream().map(InputVector::getValue).collect(Collectors.toList()));
    }

    private String setParameter(
            HttpMessage msg, List<Integer> nameValuePairPositions, List<String> values) {
        StringBuilder newBodyBuilder = new StringBuilder(msg.getRequestBody().toString());
        int offset = 0;
        for (int index = 0; index < nameValuePairPositions.size(); index++) {
            int originalPosition = nameValuePairPositions.get(index);
            String value = values.get(index);
            int idx = originalPosition - 1;

            MultipartFormParameter mpPart = this.multiPartParams.get(idx);
            LOGGER.debug(
                    "i: {} pos: {} S: {} E: {} O: {}",
                    idx,
                    originalPosition,
                    mpPart.getStart(),
                    mpPart.getEnd(),
                    offset);
            newBodyBuilder.replace(mpPart.getStart() + offset, mpPart.getEnd() + offset, value);
            offset = offset + value.length() - mpPart.getEnd() + mpPart.getStart();
        }
        String newBody = newBodyBuilder.toString();
        msg.getRequestBody().setBody(newBody);
        return newBody;
    }

    private static String getBoundary(String contentTypeHeader, HttpMessage msg) {
        int index = contentTypeHeader.lastIndexOf("boundary=");
        if (index == -1) {
            return getBoundaryFromBody(msg);
        }
        String boundary = contentTypeHeader.substring(index + 9); // "boundary=" is 9
        if (boundary.charAt(0) == '"') {
            index = boundary.lastIndexOf('"');
            boundary = boundary.substring(1, index);
        }
        // The real token is always preceded by an extra "--"
        boundary = DOUBLE_HYPHEN + boundary;

        return boundary;
    }

    private static String getBoundaryFromBody(HttpMessage msg) {
        String body = msg.getRequestBody().toString();
        if (body.startsWith(DOUBLE_HYPHEN) && hasAtleasetOneParam(body)) {
            return body.substring(0, body.indexOf(HttpHeader.CRLF));
        }
        return null;
    }

    private static boolean hasAtleasetOneParam(String body) {
        // 1 - First boundary, 2 - End boundary, 3 - End final boundary
        return body.contains(HttpHeader.CRLF) && StringUtils.countMatches(body, DOUBLE_HYPHEN) > 3;
    }
}

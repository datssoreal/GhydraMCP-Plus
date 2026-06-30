package eu.starsong.ghidra.dto;

import java.util.List;

/** Parsed body of POST /batch. */
public class BatchRequestDto {
    public boolean atomic = false;
    public List<SubRequest> requests;

    public static class SubRequest {
        public String method;
        public String path;
        public Object body;   // Gson-decoded JSON object/array/primitive, may be null
    }
}

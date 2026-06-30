package eu.starsong.ghidra.dto;

import eu.starsong.ghidra.dto.EmulationStateDto.StopReason;
import org.junit.Test;
import java.util.List;
import java.util.Map;
import static org.junit.Assert.assertEquals;

public class EmulationStateDtoTest {
    @Test
    public void ofPopulatesAllFields() {
        EmulationStateDto dto = EmulationStateDto.of(
            "0x140075000", StopReason.BREAKPOINT, 42L,
            Map.of("RIP", "0x140075000"), List.of("0x140074000", "0x140074002"), null);
        assertEquals("0x140075000", dto.pc());
        assertEquals(StopReason.BREAKPOINT, dto.stopReason());
        assertEquals(42L, dto.steps());
        assertEquals("0x140075000", dto.registers().get("RIP"));
        assertEquals(2, dto.trace().size());
    }

    @Test
    public void ofWithWatchHitPopulatesAllFields() {
        EmulationStateDto.WatchHit hit = new EmulationStateDto.WatchHit(
            "0x223018", 4, "00000000", "deadbeef", "0x140001010");
        EmulationStateDto dto = EmulationStateDto.of(
            "0x140001012", StopReason.WATCHPOINT, 7L,
            Map.of("RIP", "0x140001012"), List.of(), null, null, hit);
        assertEquals(StopReason.WATCHPOINT, dto.stopReason());
        assertEquals("0x223018", dto.watchHit().address());
        assertEquals("deadbeef", dto.watchHit().after());
        assertEquals("0x140001010", dto.watchHit().writePc());
    }
}

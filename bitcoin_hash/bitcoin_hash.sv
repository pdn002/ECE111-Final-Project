module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);

parameter num_nonces = 16;

enum logic [2:0] {IDLE, PHASE12, PHASE3} phase;
logic start12, start3;
logic done12, done3;
logic mem_clk12, mem_clk3;
logic mem_we12, mem_we3;
logic [15:0] mem_addr12, mem_addr3;
logic [ 10:0] i; // track number of cycles

logic [31:0] hout [num_nonces][8]; // stores output after first two phases

parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};


sha256onetwo #(.NUM_OF_WORDS(20)) sha256onetwo_inst (
	.clk, .reset_n, .start(start12),
	.message_addr,
	.done(done12), .mem_clk(mem_clk12), .mem_we(mem_we12),
	.mem_addr(mem_addr12),
	.hout(hout),
	.mem_read_data
);
sha256three #(.NUM_OF_WORDS(8)) sha256three_inst (
	.clk, .reset_n, .start(start3),
	.output_addr,
	.hin(hout),
	.done(done3), .mem_clk(mem_clk3), .mem_we(mem_we3),
	.mem_addr(mem_addr3),
	.mem_write_data
);

//instantiate a number of simplified sha instances in order to calculate the correct output.
always_ff @(posedge clk, negedge reset_n) begin
	if (!reset_n) begin
		phase <= IDLE;
	end 
	else case(phase)
		IDLE: begin
			if (start) begin
				phase <= PHASE12;
				start12 <= 1'b0;
				start3 <= 1'b0;
				i <= 0;
			end
		end
		PHASE12: begin
			if (i == 0) begin
				start12 <= 1'b1;
			end
			else if (i > 2) begin
				start12 <= 1'b0;
			end
			
			if (done12 == 1 && i > 2) begin
				i <= 0;
				phase <= PHASE3;
			end
			else begin
				i <= i + 1;
				phase <= PHASE12;
			end
		end
		PHASE3: begin
			if (i == 0) begin
				start3 <= 1'b1;
			end
			else if (i > 2) begin
				start3 <= 1'b0;
			end
			
			if (done3 == 1 && i > 2) begin
				i <= 0;
				phase <= IDLE;
			end
			else begin
				i <= i + 1;
				phase <= PHASE3;
			end
		end
	endcase
end

assign done = (phase == IDLE);

always_comb begin
	if (phase == PHASE12) begin
		mem_clk = mem_clk12;
		mem_we = mem_we12;
		mem_addr = mem_addr12;
	end
	else if (phase == PHASE3) begin
		mem_clk = mem_clk3;
		mem_we = mem_we3;
		mem_addr = mem_addr3;
	end
	else begin
		mem_clk = clk;
		mem_we = mem_we12;
		mem_addr = mem_addr12;
	end
end


endmodule

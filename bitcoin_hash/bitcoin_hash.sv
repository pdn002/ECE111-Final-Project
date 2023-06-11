module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);

parameter num_nonces = 16;

enum logic [4:0] {IDLE, READ, state1, state2, state3} state;
logic start1, start2, start3;
logic done1, done2, done3;
logic mem_clk1, mem_clk2, mem_clk3;
logic mem_we1, mem_we2, mem_we3;
logic [15:0] mem_addr1, mem_addr2,	 mem_addr3;
logic [ 10:0] i; // track number of cycles
logic [31:0] h0_in_p1, h1_in_p1, h2_in_p1, h3_in_p1, h4_in_p1, h5_in_p1, h6_in_p1, h7_in_p1;
logic [31:0] h0_out_p1, h1_out_p1, h2_out_p1, h3_out_p1, h4_out_p1, h5_out_p1, h6_out_p1, h7_out_p1;
logic [31:0] hout [num_nonces][8]; // stores output after first two states
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;
logic [15:0] offset;
logic [31:0] message[20];
logic[32:0] w1,w2,w3,w4;

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


//instantiate a number of simplified sha instances in order to calculate the correct output.
always_ff @(posedge clk, negedge reset_n) begin
	if (!reset_n) begin
		state <= IDLE;
	end 
	else case(state)
		IDLE: begin
			if(start) begin
				h0_in_p1 <= 32'h6a09e667; 
				h1_in_p1 <= 32'hbb67ae85; 
				h2_in_p1 <= 32'h3c6ef372; 
				h3_in_p1 <= 32'ha54ff53a;
				h4_in_p1 <= 32'h510e527f; 
				h5_in_p1 <= 32'h9b05688c; 
				h6_in_p1 <= 32'h1f83d9ab; 
				h7_in_p1 <= 32'h5be0cd19;
						
				offset <= 0;
				cur_addr <= message_addr;
				cur_we <= 1'b0;
				cur_write_data <= 0;
				start1 <= 0;
				start2 <= 0;
				start3 <= 0;
				state <= READ;
			end
			else begin
				state <= IDLE;
			end
		end
		READ: begin
			if(offset < 21) begin
				if(offset == 0) begin
					offset <= offset + 1;
					cur_we <= 1'b0;
					state <= READ;
				end
				else begin
					message[offset-1] = mem_read_data;
					offset <= offset + 1;
					cur_we <= 1'b0;
					state <= READ;
				end
			end	
			else begin
				offset <= 16'b0;
				state <= state1;
			end
		end

		state1: begin
			start1 <= 1;
			if(done1) begin
				start1 <= 0;
				w1 <= message[16];
				w2 <= message[17];
				w3 <= message[18];
				w4 <= message[19];
				state <= state2;
			end
			else begin
				state <= state1;
			end
		end
		endcase
end

assign done = (state == IDLE);

always_comb begin
	if (state == state1) begin
		mem_clk = mem_clk1;
		mem_we = mem_we1;
		mem_addr = mem_addr1;
	end
	else if (state == state2) begin
		mem_clk = mem_clk2;
		mem_we = mem_we2;
		mem_addr = mem_addr2;
	end
	else if (state == state3) begin
		mem_clk = mem_clk3;
		mem_we = mem_we3;
		mem_addr = mem_addr3;
	end
	else begin
		mem_clk = clk;
		mem_we = mem_we1;
		mem_addr = mem_addr1;
	end
end

sha256one #(.NUM_OF_WORDS(20)) sha256_p1(
.clk,
.reset_n,
.sha_start(start1),
.input_message1(message[0]),
.input_message2(message[1]),
.input_message3(message[2]),
.input_message4(message[3]),
.input_message5(message[4]),
.input_message6(message[5]),
.input_message7(message[6]),
.input_message8(message[7]),
.input_message9(message[8]),
.input_message10(message[9]),
.input_message11(message[10]),
.input_message12(message[11]),
.input_message13(message[12]),
.input_message14(message[13]),
.input_message15(message[14]),
.input_message16(message[15]),
.h0_in(h0_in_p1),
.h1_in(h1_in_p1),
.h2_in(h2_in_p1),
.h3_in(h3_in_p1),
.h4_in(h4_in_p1),
.h5_in(h5_in_p1),
.h6_in(h6_in_p1),
.h7_in(h7_in_p1),
.sha_done(sha_done_p1),
.h0_out(h0_out_p1),
.h1_out(h1_out_p1),
.h2_out(h2_out_p1),
.h3_out(h3_out_p1),
.h4_out(h4_out_p1),
.h5_out(h5_out_p1),
.h6_out(h6_out_p1),
.h7_out(h7_out_p1)
);

endmodule
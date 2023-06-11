module sha256one #(parameter integer NUM_OF_WORDS = 20)(
 input logic  clk, reset_n, sha_start,
 input logic[31:0] input_message1, input_message2, input_message3, input_message4, input_message5, input_message6, input_message7, input_message8, input_message9, input_message10, input_message11, input_message12, input_message13, input_message14, input_message15, input_message16,
 input logic[31:0] h0_in, h1_in, h2_in, h3_in, h4_in, h5_in, h6_in, h7_in,
 output logic sha_done, mem_clk,
 output logic[31:0] h0_out, h1_out, h2_out, h3_out, h4_out, h5_out, h6_out, h7_out
);

// FSM state variables 
enum logic [2:0] {IDLE, COMPUTE, WRITE, DONE} state;

// NOTE : Below mentioned frame work is for reference purpose.
// Local variables might not be complete and you might have to add more variables
// or modify these variables. Code below is more as a reference.

// Local variables
logic [31:0] w[16];
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [31:0] a, b, c, d, e, f, g, h;
logic [ 7:0] i, j, n;
logic [ 7:0] num_blocks;


// SHA256 K constants  1 column x 64 rows
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};


assign num_blocks = determine_num_blocks(NUM_OF_WORDS);
assign mem_clk = clk;

// Note : Function defined are for reference purpose. Feel free to add more functions or modify below.
// Function to determine number of blocks in memory to fetch
function logic [15:0] determine_num_blocks(input logic [31:0] size);

	logic [31:0] totalLength, numBlocks, remainder;
	totalLength = size * 32;
	numBlocks = totalLength / 512;
	remainder = totalLength % 512;
	
	if ( remainder == 0 )
		determine_num_blocks = numBlocks;
	else
		determine_num_blocks = numBlocks + 1;
	
endfunction

function logic [31:0] wtnew; // This function begins the Word Expansion
	logic [31:0] s1, s0; // internal signals
	begin
		s0 = rightrotate(w[1],7) ^ rightrotate(w[1],18) ^ (w[1] >> 3);
		s1 = rightrotate(w[14],17) ^ rightrotate(w[14],19) ^ (w[14] >> 10);
		wtnew = w[0] + s0 + w[9] + s1;
	end
endfunction


// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
	 logic [31:0] temp1, temp2;
begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch = (e & f) ^ ((~e) & g);
	 t1 = h + S1 + ch + k[t] + w;
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
    sha256_op = {t1+t2, a, b, c, d+t1, e, f, g};
end
endfunction

// Right Rotation Example : right rotate input x by r
// Lets say input x = 1111 ffff 2222 3333 4444 6666 7777 8888
// lets say r = 4
// x >> r  will result in : 0000 1111 ffff 2222 3333 4444 6666 7777 
// x << (32-r) will result in : 8888 0000 0000 0000 0000 0000 0000 0000
// final right rotate expression is = (x >> r) | (x << (32-r));
// (0000 1111 ffff 2222 3333 4444 6666 7777) | (8888 0000 0000 0000 0000 0000 0000 0000)
// final value after right rotate = 8888 1111 ffff 2222 3333 4444 6666 7777
// Right rotation function
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
   rightrotate = (x >> r) | (x << (32 - r));
endfunction


// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory
always_ff @(posedge clk, negedge reset_n)
begin
  if (!reset_n) begin
    state <= IDLE;
  end 
  else case (state)
    // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
    IDLE: begin 
	 
       if(sha_start) begin
       // Student to add rest of the code
			h0 <= h0_in; h1 <= h1_in; h2 <= h2_in; h3 <= h3_in;
			h4 <= h4_in; h5 <= h5_in; h6 <= h6_in; h7 <= h7_in;
			a <=  h0_in; b <= h1_in; c <= h2_in; d <= h3_in;
			e <= h4_in; f <= h5_in; g <= h6_in; h <= h7_in;
			
			w[0] = input_message1;
			w[1] = input_message2;
			w[2] = input_message3;
			w[3] = input_message4;
			w[4] = input_message5;
			w[5] = input_message6;
			w[6] = input_message7;
			w[7] = input_message8;
			w[8] = input_message9;
			w[9] = input_message10;
			w[10] = input_message11;
			w[11] = input_message12;
			w[12] = input_message13;
			w[13] = input_message14;
			w[14] = input_message15;
			w[15] = input_message16;
			
			i <= 1;
			j <= 0;
			n <= 0;
			
			state <= COMPUTE;
       end
		 else begin
			 state <= IDLE;
		 end
    end

    // For each block compute hash function
    // Go back to BLOCK stage after each block hash computation is completed and if
    // there are still number of message blocks available in memory otherwise
    // move to WRITE stage
    COMPUTE: begin
	// 64 processing rounds steps for 512-bit block
		if(i <= 64) begin
			if(i < 17) begin
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[i-1], i-1);
				i <= i + 1;
				state <= COMPUTE;
			end
			else if(n == 0) begin
				if(i == 17) begin
					for(int u=0;u<15;u++) begin
						w[u] <= w[u+1];
					end
					w[15] <= wtnew();
					n <= 1;
					state <= COMPUTE;
				end
				else begin
					{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], i-1);
					for(int u=0;u<15;u++) begin
						w[u] <= w[u+1];
					end
					w[15] <= wtnew();
					i <= i + 1;
					n <= 1;
					state <= COMPUTE;
				end
			end
			else begin
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], i-1);
				for(int u=0;u<15;u++) begin
					w[u] <= w[u+1];
				end
				w[15] <= wtnew();
				i <= i + 1;
				n <= 0;
				state <= COMPUTE;
			end
		end
		else begin
			state <= WRITE;
		end
	end
	WRITE: begin
		h0_out <= a + h0;
		h1_out <= b + h1;
		h2_out <= c + h2;
		h3_out <= d + h3;
		h4_out <= e + h4;
		h5_out <= f + h5;
		h6_out <= g + h6;
		h7_out <= h + h7;
		state <= DONE;
	end
	
	DONE: begin
		state <= IDLE;
	end
   endcase
  end

  
// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign sha_done = (state == DONE);
endmodule